//! Type checking, nominal value resolution, and deterministic effect analysis.
use super::ast::*;
use crate::source::{MAX_NESTING_DEPTH, SourceId, SourceRange};
use indexmap::{IndexMap, IndexSet};
use iroha_data_model::events::data::prelude::{
    AccountEventFilter, AccountEventSet, AssetDefinitionEventFilter, AssetDefinitionEventSet,
    AssetEventFilter, AssetEventSet, ConfigurationEventFilter, ConfigurationEventSet,
    DomainEventFilter, DomainEventSet, ExecutorEventFilter, ExecutorEventSet, NftEventFilter,
    NftEventSet, PeerEventFilter, PeerEventSet, RoleEventFilter, RoleEventSet, RwaEventFilter,
    RwaEventSet, TriggerEventFilter, TriggerEventSet,
};
use iroha_data_model::smart_contract::manifest::{
    ContractEnumTypeDescriptorV1, ContractEnumVariantDescriptorV1, ContractErrorMessage,
    ContractErrorTypeDescriptor, ContractErrorVariantDescriptor, ContractPermissionDescriptorV1,
    ContractPermissionScopeV1,
};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    events::{
        EventFilterBox,
        data::DataEventFilter,
        execute_trigger::ExecuteTriggerEventFilter,
        pipeline::{
            BlockEventFilter, BlockStatus, PipelineEventFilterBox, TransactionEventFilter,
            TransactionStatus,
        },
        time::{ExecutionTime, Schedule, TimeEventFilter},
    },
    nft::NftId,
    role::RoleId,
    rwa::RwaId,
    trigger::{TriggerId, action::Repeats},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::peer::PeerId;
use iroha_primitives::{
    bigint::BigInt,
    json::Json,
    numeric::{MAX_MANTISSA_BYTES, Numeric, NumericError, RoundingMode},
};
use kotodama_surface::builtins::{Builtin, BuiltinMode, BuiltinSurface, PointerConstructor};
use kotodama_surface::source_policy::{
    V1_ROUNDING_PATHS, V1_SOURCE_TYPE_NAMES, is_reserved_source_declaration,
    is_reserved_source_type_declaration,
};
use norito::json::{self, native::Number as JsonNumber};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};
/// First-release collection-iteration limit.
///
/// V1 accepts compiler-proven integer constant expressions. This cap is part of the
/// language definition and therefore identical in every build.
pub const COLLECTION_ITERATION_LIMIT: i64 = 64;
/// Maximum number of recursively expanded type nodes retained by semantic analysis.
///
/// The limit shares the fixed V1 token budget: a compact DAG of named value types cannot make the
/// compiler allocate more expanded type nodes than a source could contain lexical tokens. Expansion
/// is measured with saturating arithmetic before any recursive type materialization occurs.
pub const MAX_EXPANDED_TYPE_NODES: usize = ivm_abi::call::MAX_CALL_SCHEMA_NODES_V1;
mod call_target;
pub(crate) mod contract_imports;
use contract_imports::analyze_contract_call;
mod effect_sites;
mod id_literals;
#[cfg(test)]
mod multifile_tests;
mod trigger_lowering;
mod type_help;
mod value_traits;

pub use call_target::{CallTarget, CompilerIntrinsic, ContractMethod};
use trigger_lowering::analyze_trigger;
use value_traits::render_source_type_name;
pub use value_traits::render_type_name;
pub(crate) use value_traits::type_name;

/// Canonical nominal name for the structurally-specialized V1 query page.
const QUERY_PAGE_TYPE_NAME: &str = "QueryPage";
const QUERY_PAGE_NOMINAL_NAME: &str = "kotodama::QueryPage";
const AGGREGATE_CAPTURE_PREFIX: &str = "\0aggregate_capture#";
/// Identify only unspellable capture and projection names emitted by this module.
/// A source name beginning with `__kotodama_` is still an ordinary user binding.
pub(crate) fn aggregate_binding_origin(name: &str) -> (&str, Vec<usize>, bool) {
    let (root, suffix, capture) = if let Some(rest) = name.strip_prefix(AGGREGATE_CAPTURE_PREFIX) {
        let end = rest.find('#').unwrap_or(rest.len());
        if rest[..end].parse::<usize>().is_ok() {
            let root_end = AGGREGATE_CAPTURE_PREFIX.len() + end;
            (&name[..root_end], &name[root_end..], true)
        } else {
            return (name, Vec::new(), false);
        }
    } else if let Some(end) = name.find('#') {
        (&name[..end], &name[end..], false)
    } else {
        return (name, Vec::new(), false);
    };
    let Some(path) = suffix
        .split('#')
        .skip(1)
        .map(|part| part.parse::<usize>().ok())
        .collect::<Option<Vec<_>>>()
    else {
        return (name, Vec::new(), false);
    };
    (root, path, capture)
}
pub(crate) const LIST_LEN_INTRINSIC: &str = "__kotodama_list_len";
pub(crate) const STATE_PAGE_INTRINSIC: &str = "__kotodama_state_page";
pub(crate) const STATE_TAKE_INTRINSIC: &str = "__kotodama_state_take";
pub(crate) const LIST_GET_INTRINSIC: &str = "__kotodama_list_get";
pub(crate) const LIST_SET_INTRINSIC: &str = "__kotodama_list_set";
pub(crate) const LIST_PUSH_INTRINSIC: &str = "__kotodama_list_push";
pub(crate) const LIST_TRY_SET_INTRINSIC: &str = "__kotodama_list_try_set";
pub(crate) const LIST_TRY_PUSH_INTRINSIC: &str = "__kotodama_list_try_push";
pub(crate) const LIST_POP_INTRINSIC: &str = "__kotodama_list_pop";
pub(crate) const LIST_CONTAINS_INTRINSIC: &str = "__kotodama_list_contains";
pub(crate) const LIST_TAKE_INTRINSIC: &str = "__kotodama_list_take";
pub(crate) const LIST_ENUMERATE_INTRINSIC: &str = "__kotodama_list_enumerate";
pub(crate) const DECIMAL_MUL_DIV_ROUND_INTRINSIC: &str = "__kotodama_decimal_mul_div_round";
pub(crate) const QUANTITY_MUL_DIV_ROUND_INTRINSIC: &str = "__kotodama_quantity_mul_div_round";
pub(crate) const DECIMAL_DIV_ROUND_INTRINSIC: &str = "__kotodama_decimal_div_round";
pub(crate) const QUANTITY_DIV_ROUND_INTRINSIC: &str = "__kotodama_quantity_div_round";
pub(crate) const QUANTITY_RATIO_ROUND_INTRINSIC: &str = "__kotodama_quantity_ratio_round";
pub(crate) const DECIMAL_TO_INT_TRUNC_INTRINSIC: &str = "__kotodama_decimal_to_int_trunc";
pub(crate) const DECIMAL_TO_INT_ROUND_INTRINSIC: &str = "__kotodama_decimal_to_int_round";
pub(crate) const OPTION_OK_OR_INTRINSIC: &str = "__kotodama_option_ok_or";
pub(crate) const RESULT_OR_ERR_INTRINSIC: &str = "__kotodama_result_or_err";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FunctionEffects {
    host_side_effects: bool,
    emits_instructions: bool,
    mutates_durable_state: bool,
}
impl FunctionEffects {
    fn merge_from(&mut self, other: Self) -> bool {
        let merged = Self {
            host_side_effects: self.host_side_effects || other.host_side_effects,
            emits_instructions: self.emits_instructions || other.emits_instructions,
            mutates_durable_state: self.mutates_durable_state || other.mutates_durable_state,
        };
        let changed = *self != merged;
        *self = merged;
        changed
    }
    fn forbids_view(self) -> bool {
        self.host_side_effects || self.emits_instructions || self.mutates_durable_state
    }
}
#[derive(Clone, Default)]
struct FunctionSummary {
    direct_effects: FunctionEffects,
    calls: IndexSet<String>,
    /// Diagnostic-only source sites for the effects and calls above.
    sites: effect_sites::EffectSites,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedParam {
    pub name: String,
    pub ty: Type,
    /// Explicit source-call mode retained in module interfaces.
    pub call_mode: ParameterCallMode,
    pub is_state: bool,
}

/// Resolved type signature made available to a separately analyzed module.
///
/// Module bodies are type checked before linking.  Consequently an imported
/// call needs only the exported signature here; the callee body remains in its
/// own typed HIR until the linker combines both units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSignature {
    /// Ordered, explicitly typed parameters.
    pub params: Vec<TypedParam>,
    /// Resolved return type (`()` for a function without a return value).
    pub return_type: Type,
    /// Source-level function kind and authorization retained for test linking.
    pub modifiers: FunctionModifiers,
}

/// An authenticated compiled interface supplied by the owning source graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedContractInterface {
    /// Exact complete-artifact code identity checked by artifact admission.
    pub code_hash: iroha_crypto::Hash,
    /// Canonical signed public interface; source aliases never rewrite identities.
    pub interface: Arc<ivm_abi::metadata::EmbeddedContractInterfaceV1>,
}
/// Complete typed interface exposed by a deployable target to local test modules.
#[derive(Clone, Debug, Default)]
pub(crate) struct TestTargetEnvironment {
    pub(crate) functions: BTreeMap<String, FunctionSignature>,
    /// Qualified source aliases bound to canonical imported nominal types.
    pub(crate) types: BTreeMap<String, Type>,
    pub(crate) structs: HashMap<String, Vec<(String, Type)>>,
    pub(crate) states: IndexMap<String, Type>,
    pub(crate) consts: IndexMap<String, TypedExpr>,
    pub(crate) variant_codes: HashMap<String, u32>,
    pub(crate) error_types: BTreeMap<String, Arc<ContractErrorTypeDescriptor>>,
    pub(crate) enum_types: BTreeMap<String, Arc<ContractEnumTypeDescriptorV1>>,
    pub(crate) event_names: BTreeSet<String>,
    pub(crate) contracts: BTreeMap<String, ImportedContractInterface>,
}
pub enum Type {
    /// Opaque execution-local reference bound to an admitted compiled interface.
    ContractRef(Arc<ImportedContractInterface>),
    /// Signed adaptive-width integer in `-2^511..=2^511-1`.
    Int,
    /// Exact bounded base-10 decimal.
    Decimal,
    /// Nominal non-negative ledger quantity backed by the decimal representation.
    Quantity,
    Bool,
    String,
    /// First-class raw byte sequence.
    Bytes,
    /// Dataspace identifier used for Nexus/AXT flows.
    DataSpaceId,
    /// Atomic cross-transaction descriptor pointer.
    AxtDescriptor,
    /// Issuer-signed source-anchored remote-spend wire.
    AxtAnchoredSpendV1,
    /// Proof material supplied by dataspace verifiers.
    ProofBlob,
    /// Soracloud host request envelope pointer.
    SoracloudRequest,
    /// Soracloud host response envelope pointer.
    SoracloudResponse,
    AccountId,
    AssetDefinitionId,
    AssetId,
    NftId,
    DomainId,
    Name,
    Json,
    Unit,
    /// A closed nominal error type with an authenticated variant schema.
    ErrorEnum(Arc<ContractErrorTypeDescriptor>),
    /// A closed nominal ordinary enum, distinct from raisable errors.
    Enum(Arc<ContractEnumTypeDescriptorV1>),
    /// Execution-local confidential value available only to ZK contracts.
    Secret(Box<Type>),
    /// Durable key/value state addressed through the canonical StateMap API.
    StateMap(Box<Type>, Box<Type>),
    /// Opaque continuation bound to one durable map and canonical key schema.
    StateCursor(Box<Type>),
    /// Presence-aware value represented by one active-only compiler-owned sum handle.
    Option(Box<Type>),
    /// Success/error value represented by one active-only compiler-owned sum handle.
    Result(Box<Type>, Box<Type>),
    /// Contiguous compiler-owned list with a compile-time capacity in `1..=64`.
    List(Box<Type>, u8),
    Tuple(Vec<Type>),
    /// User-defined product type with named fields.
    Struct {
        name: String,
        fields: Arc<[(String, Type)]>,
    },
    /// Forward reference to a declared struct, resolved before typed HIR leaves analysis.
    NamedStruct(String),
}
#[derive(Debug, Clone, PartialEq)]
pub struct TypedExpr {
    pub expr: ExprKind,
    pub ty: Type,
}

pub enum ExprKind {
    /// Validated code of the nominal data or error enum carried by the expression.
    VariantCode(u32),
    Binary {
        op: BinaryOp,
        left: Box<TypedExpr>,
        right: Box<TypedExpr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<TypedExpr>,
    },
    /// Explicit numeric conversion requested by a canonical source constructor.
    ///
    /// V1 never inserts this node to make otherwise-incompatible operands or
    /// assignments type check.
    NumericCast {
        expr: Box<TypedExpr>,
    },
    /// Recoverable conversion into the nominal `quantity` domain.
    ///
    /// The error payload is the stable numeric-fault tag returned by ABI V1.
    NumericTryCast {
        expr: Box<TypedExpr>,
    },
    /// Ternary conditional expression: `cond ? then : else`.
    Conditional {
        cond: Box<TypedExpr>,
        then_expr: Box<TypedExpr>,
        else_expr: Box<TypedExpr>,
    },
    /// Expression-valued conditional blocks.
    If {
        condition: Box<TypedExpr>,
        then_branch: TypedBlock,
        else_branch: TypedBlock,
    },
    /// Expression-valued sum pattern test.
    IfLet {
        pattern: TypedSumPattern,
        value: Box<TypedExpr>,
        then_branch: TypedBlock,
        else_branch: TypedBlock,
    },
    /// Exhaustive sum match.
    Match {
        value: Box<TypedExpr>,
        arms: Vec<TypedMatchArm>,
    },
    /// Active `Option` payload with no inactive placeholder.
    OptionSome {
        value: Box<TypedExpr>,
    },
    /// Inactive `Option` value with its payload type carried only by `TypedExpr::ty`.
    OptionNone,
    /// Active `Result` success payload with no inactive error placeholder.
    ResultOk {
        value: Box<TypedExpr>,
    },
    /// Active `Result` error payload with no inactive success placeholder.
    ResultErr {
        error: Box<TypedExpr>,
    },
    /// Postfix same-family propagation.
    Propagate {
        value: Box<TypedExpr>,
    },
    Call {
        target: CallTarget,
        args: Vec<TypedExpr>,
    },
    /// A named call whose arguments remain stored in declaration order while
    /// `evaluation_order` records parameter slots in source evaluation order.
    ///
    /// Lowering evaluates the recorded slots first and only permutes the resulting temporary
    /// references into ABI order. No runtime permutation instructions are required.
    NamedCall {
        target: CallTarget,
        args: Vec<TypedExpr>,
        evaluation_order: Vec<usize>,
    },
    /// Named struct fields in source evaluation order after validation.
    StructLiteral {
        name: String,
        fields: Vec<(String, TypedExpr)>,
    },
    Tuple(Vec<TypedExpr>),
    /// Bounded list literal stored in one compiler-owned allocation.
    List(Vec<TypedExpr>),
    /// Capacity-proven bounded list comprehension.
    ListComprehension {
        expression: Box<TypedExpr>,
        item: String,
        source: Box<TypedExpr>,
        condition: Option<Box<TypedExpr>>,
    },
    /// Native canonical JSON object with decoded keys in source order.
    JsonObject(Vec<(String, TypedExpr)>),
    /// Native canonical JSON array.
    JsonArray(Vec<TypedExpr>),
    Member {
        object: Box<TypedExpr>,
        field: String,
    },
    Index {
        target: Box<TypedExpr>,
        index: Box<TypedExpr>,
    },
    /// A source `int` literal in the complete signed 512-bit domain.
    IntLiteral(BigInt),
    /// Canonical exact decimal payload paired with its source spelling.
    DecimalLiteral {
        value: Numeric,
        spelling: String,
    },
    Bool(bool),
    String(String),
    Bytes(Vec<u8>),
    Ident(String),
}
/// Semantically checked sum pattern and its active payload type.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedSumPattern {
    pub pattern: SumPattern,
    /// Exact scalar code for a nominal enum variant, otherwise absent.
    pub variant_code: Option<u32>,
    pub payload_type: Option<Type>,
}
/// One typed exhaustive match arm.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedMatchArm {
    pub pattern: TypedSumPattern,
    pub body: TypedBlock,
}

/// One typed/effect-analysis failure with an explicit stable identity.
#[derive(Debug, PartialEq, Eq)]
pub struct SemanticError {
    /// Stable machine-readable diagnostic code, independent of message text.
    pub(crate) code: &'static str,
    /// Human-readable diagnostic message without an embedded code prefix.
    pub(crate) message: String,
}
fn sem_err(code: &'static str, message: String) -> SemanticError {
    SemanticError { code, message }
}
fn compiler_worker_unavailable_semantic_error() -> SemanticError {
    sem_err(
        "K0003",
        "compiler could not allocate the bounded stack required to validate source nesting"
            .to_owned(),
    )
}
impl SemanticError {
    /// Return the stable machine-readable code.
    pub const fn code(&self) -> &'static str {
        self.code
    }
    /// Return the human-readable, prefix-free message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl std::fmt::Display for SemanticError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "[{}] {}", self.code, self.message)
    }
}
impl std::error::Error for SemanticError {}
#[derive(Debug, PartialEq)]
pub(crate) struct SemanticFailure {
    pub(crate) error: SemanticError,
    pub(crate) location: Option<SourceLocation>,
    pub(crate) diagnostic: Option<crate::semantic_diagnostics::SemanticDiagnostic>,
}
#[derive(Debug, PartialEq)]
pub(crate) struct SemanticFailures {
    pub(crate) failures: Vec<SemanticFailure>,
}
impl From<SemanticError> for SemanticFailures {
    fn from(error: SemanticError) -> Self {
        Self {
            failures: vec![SemanticFailure {
                error,
                location: None,
                diagnostic: None,
            }],
        }
    }
}
impl SemanticFailures {
    fn into_first(self) -> SemanticError {
        self.failures
            .into_iter()
            .next()
            .expect("semantic failure collections are never empty")
            .error
    }
}
/// One statement failure kept while analysis continues past it.
type RecoveredFailure = (
    SemanticError,
    Option<crate::semantic_diagnostics::SemanticDiagnostic>,
);
/// Upper bound on independent statement failures reported for one function.
const MAX_RECOVERED_FAILURES_PER_FUNCTION: usize = 8;
fn record_semantic_failure(
    failures: &mut Vec<SemanticFailure>,
    omitted: &mut usize,
    failure: SemanticFailure,
) {
    if failures.len() < crate::diagnostic::MAX_DIAGNOSTICS - 1 {
        failures.push(failure);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}
fn attach_pending_diagnostic(
    failures: &mut SemanticFailures,
    pending: Option<crate::semantic_diagnostics::SemanticDiagnostic>,
) {
    let Some(pending) = pending else {
        return;
    };
    if let Some(failure) = failures
        .failures
        .iter_mut()
        .find(|failure| failure.error.code != "K0004" && failure.diagnostic.is_none())
    {
        failure.diagnostic = Some(pending);
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct TypedProgram {
    /// Required canonical native event declarations, sorted by name.
    pub events: Vec<iroha_data_model::smart_contract::event::ContractEventDescriptorV1>,
    pub unit: SourceUnit,
    pub items: Vec<TypedItem>,
    pub states: Vec<TypedStateDecl>,
    /// Canonical declarations authenticated by artifact metadata.
    pub permissions: Vec<ContractPermissionDescriptorV1>,
    /// Canonical nominal errors advertised by this compilation.
    pub error_types: Vec<ContractErrorTypeDescriptor>,
    /// Canonical ordinary enum declarations, including private state dependencies.
    pub enum_types: Vec<ContractEnumTypeDescriptorV1>,
    /// Authenticated presentation text, independent of nominal error schemas.
    pub error_messages: Vec<ContractErrorMessage>,
    pub triggers: Vec<TypedTrigger>,
    pub message_entries: Vec<MessageEntry>,
    /// Stable typed/effect-HIR metadata keyed independently of Rust addresses.
    pub hir_nodes: BTreeMap<TypedHirNodeId, TypedHirNode>,
    /// Stable immutable source files retained by the typed-HIR graph for exact
    /// diagnostics and hash-keyed debug sidecars.
    pub source_files: BTreeMap<crate::source::SourceId, crate::source::SourceFile>,
    /// Whether this HIR was analyzed with local test capabilities enabled.
    ///
    /// Production artifact builders reject test-capable HIR even when a caller removes the
    /// source-level test declarations after analysis. This provenance bit keeps the mode boundary
    /// fail-closed across typed-module linking and compiler-internal typed-HIR builds.
    pub test_support_enabled: bool,
}

/// Graph-stable identity of one typed HIR node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypedHirNodeId {
    /// Source unit that owns the local HIR identity.
    pub source: crate::source::SourceId,
    /// Stable source-unit-local identity.
    pub local: HirId,
}
/// Type and resolver target retained for one successfully typed expression.
#[derive(Debug, Clone, PartialEq)]
pub struct TypedHirNode {
    /// Graph-stable identity.
    pub id: TypedHirNodeId,
    /// Exact source range when source-backed.
    pub source: Option<crate::source::SourceRange>,
    /// Authoritative resolver target for named nodes.
    pub target: Option<crate::resolved::ResolvedTarget>,
    /// Final semantic type.
    pub ty: Type,
}
#[derive(Debug, PartialEq, Clone)]
pub struct TypedStateDecl {
    pub name: String,
    pub ty: Type,
    /// Exact source range of the state declaration, when source-backed.
    pub source: Option<crate::source::SourceRange>,
}
/// Mutable semantic state for exactly one compilation.
///
/// Keeping these registries in an owned context prevents independent compiler
/// sessions from observing one another's declarations while still allowing the
/// semantic pass to build forward-reference tables before checking bodies.
#[derive(Default)]
pub struct SemanticContext {
    structs: RefCell<HashMap<String, Vec<(String, Type)>>>,
    states: RefCell<IndexMap<String, Type>>,
    consts: RefCell<IndexMap<String, TypedExpr>>,
    function_returns: RefCell<HashMap<String, Type>>,
    function_modifiers: RefCell<HashMap<String, FunctionModifiers>>,
    permissions: RefCell<BTreeMap<String, ContractPermissionScopeV1>>,
    function_params: RefCell<HashMap<String, Vec<TypedParam>>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    global_declarations: RefCell<HashSet<String>>,
    current_function_modifiers: RefCell<Option<FunctionModifiers>>,
    current_function_name: RefCell<Option<String>>,
    current_mutable_bindings: RefCell<HashSet<String>>,
    trigger_callback_functions: RefCell<HashSet<String>>,
    current_state_param_names: RefCell<HashSet<String>>,
    zk_enabled: bool,
    test_builtins_enabled: bool,
    /// The analyzed source is a standalone `koto_test` module: every function in it is test-only,
    /// so private helpers may call test builtins too.
    standalone_test_module: std::cell::Cell<bool>,
    variant_codes: RefCell<HashMap<String, u32>>,
    error_types: RefCell<BTreeMap<String, Arc<ContractErrorTypeDescriptor>>>,
    enum_types: RefCell<BTreeMap<String, Arc<ContractEnumTypeDescriptorV1>>>,
    event_names: RefCell<BTreeSet<String>>,
    contracts: RefCell<BTreeMap<String, ImportedContractInterface>>,
    package_identity: RefCell<Option<String>>,
    external_functions: RefCell<BTreeMap<String, FunctionSignature>>,
    external_types: RefCell<BTreeMap<String, Type>>,
    external_states: RefCell<IndexMap<String, Type>>,
    resolved_arenas: RefCell<BTreeMap<SourceId, Arc<crate::resolved::ResolvedArena>>>,
    resolved_declaration_sources: RefCell<BTreeMap<String, SourceRange>>,
    resolved_binding_types: RefCell<BTreeMap<(SourceId, crate::resolved::BindingId), Type>>,
    typed_hir_nodes: RefCell<BTreeMap<TypedHirNodeId, Type>>,
    pending_diagnostic: RefCell<Option<crate::semantic_diagnostics::SemanticDiagnostic>>,
    /// Unannotated locals of the current function and their `let` statements.
    inferred_locals: RefCell<HashMap<String, crate::source::SourceRange>>,
    /// Declared return type range of the function being analyzed.
    current_return_source: RefCell<Option<crate::source::SourceRange>>,
    /// Whether a failing statement of the current function body may be
    /// recorded and skipped so later independent errors are also reported.
    statement_recovery: Cell<bool>,
    /// Statement failures recovered in the current function, in source order.
    recovered_failures: RefCell<Vec<RecoveredFailure>>,
    /// Further failures of the last failed function, reported after its first.
    extra_failures: RefCell<Vec<RecoveredFailure>>,
    required_list_capacity: RefCell<Option<u8>>,
    resolved_named_types: RefCell<HashMap<String, Type>>,
    resolved_named_type_resources: RefCell<HashMap<String, ExpandedTypeResources>>,
    next_synthetic_binding: Cell<usize>,
}
impl SemanticContext {
    /// Construct an empty per-compilation semantic context.
    pub fn new() -> Self {
        Self::default()
    }
    /// Construct a context with ZK-only language capabilities enabled by build policy.
    pub fn with_zk_enabled(zk_enabled: bool) -> Self {
        Self {
            zk_enabled,
            ..Self::default()
        }
    }
    /// Construct a context with compiler-owned execution capabilities.
    pub fn with_capabilities(zk_enabled: bool, test_builtins_enabled: bool) -> Self {
        Self {
            zk_enabled,
            test_builtins_enabled,
            ..Self::default()
        }
    }
    /// Bind nominal declarations to the exact locked package identity.
    pub fn set_package_identity(&self, identity: impl Into<String>) {
        self.package_identity.replace(Some(identity.into()));
    }
    fn swap_state(&self, other: &Self) {
        self.standalone_test_module
            .swap(&other.standalone_test_module);
        self.structs.swap(&other.structs);
        self.states.swap(&other.states);
        self.consts.swap(&other.consts);
        self.function_returns.swap(&other.function_returns);
        self.function_modifiers.swap(&other.function_modifiers);
        self.function_params.swap(&other.function_params);
        self.function_summaries.swap(&other.function_summaries);
        self.global_declarations.swap(&other.global_declarations);
        self.current_function_modifiers
            .swap(&other.current_function_modifiers);
        self.current_function_name
            .swap(&other.current_function_name);
        self.current_mutable_bindings
            .swap(&other.current_mutable_bindings);
        self.trigger_callback_functions
            .swap(&other.trigger_callback_functions);
        self.current_state_param_names
            .swap(&other.current_state_param_names);
        self.variant_codes.swap(&other.variant_codes);
        self.error_types.swap(&other.error_types);
        self.enum_types.swap(&other.enum_types);
        self.event_names.swap(&other.event_names);
        self.contracts.swap(&other.contracts);
        self.package_identity.swap(&other.package_identity);
        self.external_functions.swap(&other.external_functions);
        self.external_types.swap(&other.external_types);
        self.external_states.swap(&other.external_states);
        self.resolved_arenas.swap(&other.resolved_arenas);
        self.resolved_declaration_sources
            .swap(&other.resolved_declaration_sources);
        self.resolved_binding_types
            .swap(&other.resolved_binding_types);
        self.typed_hir_nodes.swap(&other.typed_hir_nodes);
        self.pending_diagnostic.swap(&other.pending_diagnostic);
        self.inferred_locals.swap(&other.inferred_locals);
        self.statement_recovery.swap(&other.statement_recovery);
        self.recovered_failures.swap(&other.recovered_failures);
        self.extra_failures.swap(&other.extra_failures);
        self.current_return_source
            .swap(&other.current_return_source);
        self.required_list_capacity
            .swap(&other.required_list_capacity);
        self.resolved_named_types.swap(&other.resolved_named_types);
        self.resolved_named_type_resources
            .swap(&other.resolved_named_type_resources);
        self.next_synthetic_binding
            .swap(&other.next_synthetic_binding);
    }
    fn run_on_compiler_stack<T, F>(
        &self,
        operation: F,
    ) -> Result<T, crate::session::CompilerWorkerUnavailable>
    where
        T: Send,
        F: FnOnce(&Self) -> T + Send,
    {
        let worker_context = Self::with_capabilities(self.zk_enabled, self.test_builtins_enabled);
        self.swap_state(&worker_context);

        // Keep a recoverable owner outside the spawn closure. If the OS cannot
        // create the bounded worker, the caller's prior context state can be
        // restored without dropping attacker-shaped types on the caller stack.
        let pending_context = Arc::new(std::sync::Mutex::new(Some(worker_context)));
        let worker_pending_context = Arc::clone(&pending_context);
        match crate::session::run_with_compiler_stack(move || {
            let worker_context = worker_pending_context
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take()
                .expect("semantic worker context is available exactly once");
            let result = operation(&worker_context);
            (worker_context, result)
        }) {
            Ok((worker_context, result)) => {
                self.swap_state(&worker_context);
                Ok(result)
            }
            Err(error) => {
                let worker_context = pending_context
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take()
                    .expect("failed worker spawn retains the semantic context");
                self.swap_state(&worker_context);
                Err(error)
            }
        }
    }
    /// Analyze one parsed program using only state owned by this context.
    ///
    /// The context is reset before every call so callers may reuse it
    /// sequentially without leaking declarations between source units.
    pub fn analyze(&self, program: &Program) -> Result<TypedProgram, SemanticError> {
        self.run_on_compiler_stack(move |context| {
            context
                .analyze_all(program)
                .map_err(SemanticFailures::into_first)
        })
        .unwrap_or_else(|_| Err(compiler_worker_unavailable_semantic_error()))
    }
    /// Analyze one source unit with explicitly resolved imported functions.
    ///
    /// The external names must be fully qualified source names such as `math::add`. They
    /// participate in ordinary type checking but are not treated as local definitions for recursion
    /// or effect analysis. The typed-HIR linker reruns those whole-program analyses after resolving
    /// all calls to their final linked symbols.
    pub fn analyze_with_external_functions(
        &self,
        program: &Program,
        external_functions: &BTreeMap<String, FunctionSignature>,
    ) -> Result<TypedProgram, SemanticError> {
        self.run_on_compiler_stack(move |context| {
            context
                .analyze_all_with_external_functions(program, external_functions)
                .map_err(SemanticFailures::into_first)
        })
        .unwrap_or_else(|_| Err(compiler_worker_unavailable_semantic_error()))
    }
    pub(crate) fn analyze_all_with_external_functions(
        &self,
        program: &Program,
        external_functions: &BTreeMap<String, FunctionSignature>,
    ) -> Result<TypedProgram, SemanticFailures> {
        self.analyze_all_with_external_environment(program, external_functions, &IndexMap::new())
    }
    fn analyze_all_with_external_environment(
        &self,
        program: &Program,
        external_functions: &BTreeMap<String, FunctionSignature>,
        external_states: &IndexMap<String, Type>,
    ) -> Result<TypedProgram, SemanticFailures> {
        self.reset();
        self.external_functions.replace(external_functions.clone());
        self.external_states.replace(external_states.clone());
        analyze_with_context(self, program)
    }
    /// Resolve the function interface of one source unit without inspecting function bodies.
    ///
    /// This is the resolution pass used to make locked module exports
    /// available while every module is still analyzed independently.
    pub fn resolve_function_signatures(
        &self,
        program: &Program,
    ) -> Result<BTreeMap<String, FunctionSignature>, SemanticError> {
        self.run_on_compiler_stack(move |context| {
            context.reset();
            context.resolve_function_signatures_inline(program, &BTreeMap::new())
        })
        .unwrap_or_else(|_| Err(compiler_worker_unavailable_semantic_error()))
    }
    fn resolve_function_signatures_inline(
        &self,
        program: &Program,
        imported_types: &BTreeMap<String, Type>,
    ) -> Result<BTreeMap<String, FunctionSignature>, SemanticError> {
        self.install_external_types(imported_types);
        register_enum_types(self, program)?;
        register_event_names(self, program)?;
        let struct_names = validate_declaration_uniqueness(program)?;
        predeclare_integer_constants(self, program)?;
        let mut all_structs = self.structs.borrow().clone();
        all_structs.extend(struct_names.iter().cloned().map(|name| (name, Vec::new())));
        self.structs.replace(all_structs);
        let mut structs = self.structs.borrow().clone();
        for item in &program.items {
            let (Item::Struct(definition) | Item::Event(definition)) = item else {
                continue;
            };
            let mut fields = Vec::with_capacity(definition.fields.len());
            for (name, ty) in &definition.fields {
                fields.push((name.clone(), convert_type_expr(self, ty)?));
            }
            structs.insert(definition.name.clone(), fields);
        }
        self.structs.replace(structs);
        validate_acyclic_value_structs(self, &struct_names)?;
        let resolution_plan = validate_struct_resolution_budget(self, &struct_names)
            .map_err(|failure| failure.error)?;
        install_canonical_struct_types(self, resolution_plan, program);

        let mut signatures = BTreeMap::new();
        for item in &program.items {
            let Item::Function(function) = item else {
                continue;
            };
            let mut params = Vec::with_capacity(function.params.len());
            for param in &function.params {
                params.push(parse_declared_param_type(self, param, &function.modifiers)?);
            }
            let return_type = parse_declared_type(self, &function.ret_ty)?.unwrap_or(Type::Unit);
            signatures.insert(
                function.name.clone(),
                FunctionSignature {
                    params,
                    return_type,
                    modifiers: function.modifiers.clone(),
                },
            );
        }
        Ok(signatures)
    }
    pub(crate) fn resolve_resolved_function_signatures(
        &self,
        program: &crate::resolved::ResolvedProgram,
    ) -> Result<BTreeMap<String, FunctionSignature>, SemanticError> {
        self.resolve_resolved_function_signatures_all(program)
            .map_err(SemanticFailures::into_first)
    }
    pub(crate) fn resolve_resolved_function_signatures_all(
        &self,
        program: &crate::resolved::ResolvedProgram,
    ) -> Result<BTreeMap<String, FunctionSignature>, SemanticFailures> {
        self.resolve_resolved_function_signatures_with_types(program, &BTreeMap::new())
    }
    pub(crate) fn resolve_resolved_function_signatures_with_types(
        &self,
        program: &crate::resolved::ResolvedProgram,
        imported_types: &BTreeMap<String, Type>,
    ) -> Result<BTreeMap<String, FunctionSignature>, SemanticFailures> {
        self.resolve_resolved_function_signatures_with_environment(
            program,
            &TestTargetEnvironment {
                types: imported_types.clone(),
                ..TestTargetEnvironment::default()
            },
        )
    }
    pub(crate) fn resolve_resolved_function_signatures_with_environment(
        &self,
        program: &crate::resolved::ResolvedProgram,
        environment: &TestTargetEnvironment,
    ) -> Result<BTreeMap<String, FunctionSignature>, SemanticFailures> {
        self.reset();
        self.consts.replace(environment.consts.clone());
        self.resolved_arenas.replace(
            program
                .arenas()
                .map(|arena| (arena.source(), arena))
                .collect(),
        );
        let result = self.resolve_function_signatures_inline(program.program(), &environment.types);
        let pending = self.take_diagnostic();
        self.resolved_arenas.borrow_mut().clear();
        self.resolved_declaration_sources.borrow_mut().clear();
        result.map_err(|error| {
            let mut failures = SemanticFailures::from(error);
            attach_pending_diagnostic(&mut failures, pending);
            failures
        })
    }
    /// Evaluate this prepared unit's constants for explicit module exports.
    pub(crate) fn declared_constants(
        &self,
        program: &crate::resolved::ResolvedProgram,
    ) -> Result<BTreeMap<String, TypedExpr>, SemanticFailures> {
        let declarations = program
            .program()
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Const(declaration) => Some(declaration),
                _ => None,
            })
            .collect::<Vec<_>>();
        let own_names = declarations
            .iter()
            .map(|declaration| declaration.name.as_str())
            .collect::<BTreeSet<_>>();
        // Signature preparation predeclares local integers for bounded type
        // expressions. Value initializers still obey declaration-before-use.
        let initial = self
            .consts
            .borrow()
            .iter()
            .filter(|(name, _)| !own_names.contains(name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let previous = self.resolved_arenas.replace(
            program
                .arenas()
                .map(|arena| (arena.source(), arena))
                .collect(),
        );
        let result = evaluate_constant_declarations(self, declarations.iter().copied(), initial);
        self.resolved_arenas.replace(previous);
        let pending = self.take_diagnostic();
        result
            .map_err(|mut failures| {
                attach_pending_diagnostic(&mut failures, pending);
                failures
            })
            .map(|values| {
                let exported = values
                    .iter()
                    .filter(|(name, _)| own_names.contains(name.as_str()))
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect();
                self.consts.replace(values);
                exported
            })
    }
    pub(crate) fn analyze_resolved_with_test_target(
        &self,
        program: &crate::resolved::ResolvedProgram,
        environment: &TestTargetEnvironment,
    ) -> Result<TypedProgram, SemanticFailures> {
        self.analyze_resolved_environment(program, environment)
    }
    pub(crate) fn test_target_environment(
        &self,
        functions: BTreeMap<String, FunctionSignature>,
        states: IndexMap<String, Type>,
    ) -> TestTargetEnvironment {
        TestTargetEnvironment {
            functions,
            types: self
                .external_types
                .borrow()
                .iter()
                .map(|(name, ty)| (name.clone(), ty.clone()))
                .chain(
                    self.resolved_named_types
                        .borrow()
                        .iter()
                        .map(|(name, ty)| (name.clone(), ty.clone())),
                )
                .collect(),
            structs: self.structs.borrow().clone(),
            states,
            consts: self.consts.borrow().clone(),
            variant_codes: self.variant_codes.borrow().clone(),
            error_types: self.error_types.borrow().clone(),
            enum_types: self.enum_types.borrow().clone(),
            event_names: self.event_names.borrow().clone(),
            contracts: self.contracts.borrow().clone(),
        }
    }
    pub(crate) fn analyze_all(&self, program: &Program) -> Result<TypedProgram, SemanticFailures> {
        self.reset();
        analyze_with_context(self, program)
    }
    /// Type and effect-check a program only after fail-closed named-HIR resolution.
    pub(crate) fn analyze_resolved(
        &self,
        program: &crate::resolved::ResolvedProgram,
    ) -> Result<TypedProgram, SemanticFailures> {
        self.analyze_resolved_environment(program, &TestTargetEnvironment::default())
    }
    fn analyze_resolved_environment(
        &self,
        program: &crate::resolved::ResolvedProgram,
        environment: &TestTargetEnvironment,
    ) -> Result<TypedProgram, SemanticFailures> {
        self.analyze_resolved_environment_with_editor_facts(program, environment, false)
            .0
    }
    /// Retain successfully typed subexpressions for editor queries even when another expression fails.
    pub(crate) fn analyze_editor(
        &self,
        program: &crate::resolved::ResolvedProgram,
        external_functions: BTreeMap<String, FunctionSignature>,
        imported_types: BTreeMap<String, Type>,
    ) -> (
        Result<TypedProgram, SemanticFailures>,
        BTreeMap<crate::resolved::BindingId, Type>,
        Vec<TypedHirNode>,
    ) {
        self.analyze_resolved_environment_with_editor_facts(
            program,
            &TestTargetEnvironment {
                functions: external_functions,
                types: imported_types,
                ..TestTargetEnvironment::default()
            },
            true,
        )
    }
    /// Retain editor facts using the complete explicit module environment.
    pub(crate) fn analyze_editor_with_environment(
        &self,
        program: &crate::resolved::ResolvedProgram,
        environment: &TestTargetEnvironment,
    ) -> (
        Result<TypedProgram, SemanticFailures>,
        BTreeMap<crate::resolved::BindingId, Type>,
        Vec<TypedHirNode>,
    ) {
        self.analyze_resolved_environment_with_editor_facts(program, environment, true)
    }
    fn analyze_resolved_environment_with_editor_facts(
        &self,
        program: &crate::resolved::ResolvedProgram,
        environment: &TestTargetEnvironment,
        retain_editor_facts: bool,
    ) -> (
        Result<TypedProgram, SemanticFailures>,
        BTreeMap<crate::resolved::BindingId, Type>,
        Vec<TypedHirNode>,
    ) {
        self.reset();
        self.standalone_test_module
            .set(self.test_builtins_enabled && program.program().test_target.is_some());
        self.resolved_arenas.replace(
            program
                .arenas()
                .map(|arena| (arena.source(), arena))
                .collect(),
        );
        self.resolved_declaration_sources.replace(
            program
                .symbols()
                .map(|symbol| (symbol.name.clone(), symbol.source))
                .collect(),
        );
        self.external_functions
            .replace(environment.functions.clone());
        self.external_states.replace(environment.states.clone());
        self.structs.replace(environment.structs.clone());
        self.consts.replace(environment.consts.clone());
        self.variant_codes
            .replace(environment.variant_codes.clone());
        self.error_types.replace(environment.error_types.clone());
        self.enum_types.replace(environment.enum_types.clone());
        self.event_names.replace(environment.event_names.clone());
        self.contracts.replace(environment.contracts.clone());
        self.install_external_types(&environment.types);
        let mut result = analyze_with_context(self, program.program());
        let pending = self.take_diagnostic();
        if let Err(failures) = &mut result {
            attach_pending_diagnostic(failures, pending);
        }
        let primary_source = program.arena().source();
        let bindings = self
            .resolved_binding_types
            .borrow()
            .iter()
            .filter(|((source, _), _)| retain_editor_facts && *source == primary_source)
            .map(|((_, id), ty)| (*id, ty.clone()))
            .collect();
        let arenas = self.resolved_arenas.borrow();
        let nodes = self
            .typed_hir_nodes
            .borrow()
            .iter()
            .filter(|_| retain_editor_facts)
            .filter_map(|(id, ty)| {
                let node = arenas.get(&id.source)?.node(id.local)?;
                Some(TypedHirNode {
                    id: *id,
                    source: node.source,
                    target: node.target,
                    ty: ty.clone(),
                })
            })
            .collect();
        drop(arenas);
        self.resolved_arenas.borrow_mut().clear();
        self.resolved_declaration_sources.borrow_mut().clear();
        self.resolved_binding_types.borrow_mut().clear();
        self.typed_hir_nodes.borrow_mut().clear();
        self.required_list_capacity.borrow_mut().take();
        (
            result.map(|mut typed| {
                program.attach_sources(&mut typed);
                typed
            }),
            bindings,
            nodes,
        )
    }
    fn install_external_types(&self, types: &BTreeMap<String, Type>) {
        self.external_types.replace(types.clone());
        for (alias, ty) in types {
            match ty {
                Type::Struct { fields, .. } => {
                    self.structs
                        .borrow_mut()
                        .insert(alias.clone(), fields.to_vec());
                }
                Type::Enum(descriptor) => {
                    self.enum_types
                        .borrow_mut()
                        .insert(alias.clone(), Arc::clone(descriptor));
                    for variant in &descriptor.variants {
                        self.variant_codes
                            .borrow_mut()
                            .insert(format!("{alias}::{}", variant.name), variant.code);
                    }
                }
                Type::ErrorEnum(descriptor) => {
                    self.error_types
                        .borrow_mut()
                        .insert(alias.clone(), Arc::clone(descriptor));
                    for variant in &descriptor.variants {
                        self.variant_codes
                            .borrow_mut()
                            .insert(format!("{alias}::{}", variant.name), variant.code);
                    }
                }
                _ => {}
            }
        }
    }
    pub(crate) fn declared_nominal_types(
        &self,
        program: &Program,
    ) -> Result<BTreeMap<String, Type>, SemanticError> {
        let mut types = BTreeMap::new();
        for item in &program.items {
            match item {
                Item::Struct(definition) => {
                    types.insert(
                        definition.name.clone(),
                        resolve_struct_type_with_context(
                            self,
                            &Type::NamedStruct(definition.name.clone()),
                        )?,
                    );
                }
                Item::Enum(definition) => {
                    let ty = declared_enum_type(self, &definition.name).ok_or_else(|| {
                        SemanticError {
                            code: "E_INTERNAL_RESOLUTION",
                            message: "resolved enum declaration has no canonical descriptor".into(),
                        }
                    })?;
                    types.insert(definition.name.clone(), ty);
                }
                _ => {}
            }
        }
        Ok(types)
    }
    fn expression_source(&self, expression: &Expr) -> Option<crate::source::SourceRange> {
        self.resolved_source(expression.hir_id(), expression.source())
    }
    fn statement_source(&self, statement: &Statement) -> Option<crate::source::SourceRange> {
        self.resolved_source(statement.hir_id(), statement.source())
    }
    fn type_source(&self, ty: &TypeExpr) -> Option<crate::source::SourceRange> {
        self.resolved_source(ty.hir_id(), ty.source())
    }
    fn resolved_source(
        &self,
        id: Option<HirId>,
        raw: Option<crate::source::SourceRange>,
    ) -> Option<crate::source::SourceRange> {
        let Ok(Some(arena)) = self.arena_for_source(raw) else {
            return raw;
        };
        id.and_then(|id| arena.node(id))
            .and_then(|node| node.source)
    }
    fn arena_for_source(
        &self,
        source: Option<SourceRange>,
    ) -> Result<Option<Arc<crate::resolved::ResolvedArena>>, SemanticError> {
        let arenas = self.resolved_arenas.borrow();
        if arenas.is_empty() {
            return Ok(None);
        }
        let arena = match source {
            Some(source) => arenas.get(&source.source),
            None if arenas.len() == 1 => arenas.values().next(),
            None => None,
        };
        arena.cloned().map(Some).ok_or_else(|| SemanticError {
            code: "E_INTERNAL_RESOLUTION",
            message: "resolved node does not identify an authority source arena".into(),
        })
    }
    fn resolved_node(
        &self,
        id: Option<HirId>,
        kind: crate::resolved::ResolvedNodeKind,
        source: Option<crate::source::SourceRange>,
    ) -> Result<Option<crate::resolved::ResolvedNode>, SemanticError> {
        let Some(arena) = self.arena_for_source(source)? else {
            return Ok(None);
        };
        let id = id.ok_or_else(|| SemanticError {
            code: "E_INTERNAL_RESOLUTION",
            message: "production semantic input contains an unwrapped AST node".into(),
        })?;
        let node = arena.node(id).cloned().ok_or_else(|| SemanticError {
            code: "E_INTERNAL_RESOLUTION",
            message: format!(
                "resolved-HIR node {} is absent from its authority arena",
                id.0
            ),
        })?;
        if node.kind != kind || node.source != source {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!(
                    "resolved-HIR node {} metadata diverged from its authority arena",
                    id.0
                ),
            });
        }
        Ok(Some(node))
    }
    fn expression_target(
        &self,
        expression: &Expr,
    ) -> Result<Option<crate::resolved::ResolvedTarget>, SemanticError> {
        Ok(self
            .resolved_node(
                expression.hir_id(),
                crate::resolved::ResolvedNodeKind::Expression,
                expression.source(),
            )?
            .and_then(|node| node.target))
    }
    fn validate_statement_node(
        &self,
        statement: &Statement,
    ) -> Result<Option<crate::resolved::ResolvedNode>, SemanticError> {
        self.resolved_node(
            statement.hir_id(),
            crate::resolved::ResolvedNodeKind::Statement,
            statement.source(),
        )
    }
    fn validate_type_node(
        &self,
        ty: &TypeExpr,
    ) -> Result<Option<crate::resolved::ResolvedNode>, SemanticError> {
        self.resolved_node(
            ty.hir_id(),
            crate::resolved::ResolvedNodeKind::Type,
            ty.source(),
        )
    }
    fn validate_value_target(
        &self,
        expression: &Expr,
        name: &str,
        vars: &HashMap<String, Type>,
    ) -> Result<Option<(crate::resolved::ResolvedValueTarget, Option<Type>)>, SemanticError> {
        use crate::resolved::{ResolvedTarget, ResolvedValueTarget};
        let Some(target) = self.expression_target(expression)? else {
            if !self.resolved_arenas.borrow().is_empty() {
                return Err(SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: format!("value `{name}` has no resolver-produced target"),
                });
            }
            return Ok(None);
        };
        let ResolvedTarget::Value(target) = target else {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!("value `{name}` carries a non-value resolver target"),
            });
        };
        let arena = self
            .arena_for_source(expression.source())?
            .expect("resolved target requires arena");
        let ty = match target {
            ResolvedValueTarget::Binding(binding) => {
                let binding = arena.binding(binding).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "value target references an unknown binding".into(),
                })?;
                if binding.name != name {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "value spelling `{name}` diverges from binding `{}`",
                            binding.name
                        ),
                    });
                }
                let node = expression.hir_id().ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "resolved value use lost its stable HIR identity".into(),
                })?;
                if !arena.binding_visible_at(binding.id, node) {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!("binding `{name}` is outside the resolved lexical scope"),
                    });
                }
                let ty = vars
                    .get(&binding.name)
                    .cloned()
                    .ok_or_else(|| SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "binding `{name}` is not visible in its resolved lexical scope"
                        ),
                    })?;
                let mut binding_types = self.resolved_binding_types.borrow_mut();
                if let Some(previous) =
                    binding_types.insert((arena.source(), binding.id), ty.clone())
                    && previous != ty
                {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!("binding `{name}` acquired inconsistent semantic types"),
                    });
                }
                Some(ty)
            }
            ResolvedValueTarget::State(symbol) | ResolvedValueTarget::Const(symbol) => {
                let symbol = arena.symbol(symbol).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "value target references an unknown symbol".into(),
                })?;
                if symbol.name != name {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "value spelling `{name}` diverges from symbol `{}`",
                            symbol.name
                        ),
                    });
                }
                None
            }
            ResolvedValueTarget::VariantCode(_)
            | ResolvedValueTarget::ImportedVariant
            | ResolvedValueTarget::Intrinsic
            | ResolvedValueTarget::ExternalState
            | ResolvedValueTarget::ExternalConst => None,
        };
        Ok(Some((target, ty)))
    }
    fn list_receiver_is_mutable(
        &self,
        expression: &Expr,
        name: &str,
        vars: &HashMap<String, Type>,
    ) -> Result<bool, SemanticError> {
        use crate::resolved::ResolvedValueTarget;
        let Some((target, _)) = self.validate_value_target(expression, name, vars)? else {
            return Ok(self.current_mutable_bindings.borrow().contains(name));
        };
        let ResolvedValueTarget::Binding(binding) = target else {
            return Ok(false);
        };
        let arena = self
            .arena_for_source(expression.source())?
            .expect("resolved binding requires arena");
        let binding = arena.binding(binding).ok_or_else(|| SemanticError {
            code: "E_INTERNAL_RESOLUTION",
            message: "List mutator receiver references an unknown lexical binding".into(),
        })?;
        Ok(binding.mutable)
    }
    fn validate_call_target(
        &self,
        expression: &Expr,
        source_name: &str,
        normalized_name: &str,
        implicit_receiver: bool,
    ) -> Result<(), SemanticError> {
        use crate::resolved::{ResolvedCallTarget, ResolvedSymbolKind, ResolvedTarget};
        let Some(target) = self.expression_target(expression)? else {
            if !self.resolved_arenas.borrow().is_empty() {
                return Err(SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: format!("call `{source_name}` has no resolver-produced target"),
                });
            }
            return Ok(());
        };
        let ResolvedTarget::Call(target) = target else {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!("call `{source_name}` carries a non-call resolver target"),
            });
        };
        let arena = self
            .arena_for_source(expression.source())?
            .expect("resolved target requires arena");
        match target {
            ResolvedCallTarget::Function(symbol) => {
                let symbol = arena.symbol(symbol).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "call references an unknown function symbol".into(),
                })?;
                if symbol.kind != ResolvedSymbolKind::Function || symbol.name != source_name {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "function call `{source_name}` diverges from resolver symbol `{}`",
                            symbol.name
                        ),
                    });
                }
            }
            ResolvedCallTarget::Builtin(builtin) => {
                if normalized_name != builtin.name() {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "builtin call `{source_name}` diverges from its registry target"
                        ),
                    });
                }
            }
            ResolvedCallTarget::Method if !implicit_receiver => {
                return Err(SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: format!("method target `{source_name}` lost its receiver"),
                });
            }
            ResolvedCallTarget::Method
            | ResolvedCallTarget::Intrinsic
            | ResolvedCallTarget::External => {}
            ResolvedCallTarget::Struct(symbol) => {
                let symbol = arena.symbol(symbol).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "positional struct call references an unknown symbol".into(),
                })?;
                if symbol.kind != ResolvedSymbolKind::Struct || symbol.name != source_name {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "positional struct call `{source_name}` diverges from resolver symbol `{}`",
                            symbol.name
                        ),
                    });
                }
            }
        }
        Ok(())
    }
    fn validate_assignment_target(
        &self,
        node: Option<&crate::resolved::ResolvedNode>,
        name: &str,
    ) -> Result<(), SemanticError> {
        use crate::resolved::{ResolvedTarget, ResolvedValueTarget};
        let Some(node) = node else {
            return Ok(());
        };
        let Some(target) = node.target.as_ref() else {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!("assignment `{name}` has no resolver-produced target"),
            });
        };
        let ResolvedTarget::Assignment(target) = target else {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!("assignment `{name}` carries a non-assignment resolver target"),
            });
        };
        let arena = self
            .arena_for_source(node.source)?
            .expect("resolved target requires arena");
        match target {
            ResolvedValueTarget::Binding(binding) => {
                let binding = arena.binding(*binding).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "assignment references an unknown binding".into(),
                })?;
                if binding.name != name || !arena.binding_visible_at(binding.id, node.id) {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "assignment `{name}` diverges from its lexical binding target"
                        ),
                    });
                }
            }
            ResolvedValueTarget::State(symbol) | ResolvedValueTarget::Const(symbol) => {
                let symbol = arena.symbol(*symbol).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "assignment references an unknown symbol".into(),
                })?;
                if symbol.name != name {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "assignment `{name}` diverges from resolver symbol `{}`",
                            symbol.name
                        ),
                    });
                }
            }
            ResolvedValueTarget::ExternalState => {}
            ResolvedValueTarget::ExternalConst
            | ResolvedValueTarget::VariantCode(_)
            | ResolvedValueTarget::ImportedVariant
            | ResolvedValueTarget::Intrinsic => {
                return Err(SemanticError {
                    code: "E_TYPE_ANNOTATION_MISMATCH",
                    message: format!("resolved value `{name}` is not assignable"),
                });
            }
        }
        Ok(())
    }
    fn validate_struct_literal_target(
        &self,
        expression: &Expr,
        name: &str,
    ) -> Result<(), SemanticError> {
        use crate::resolved::{ResolvedSymbolKind, ResolvedTarget};
        let Some(target) = self.expression_target(expression)? else {
            if !self.resolved_arenas.borrow().is_empty() {
                return Err(SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: format!("struct literal `{name}` has no resolver-produced target"),
                });
            }
            return Ok(());
        };
        match target {
            ResolvedTarget::StructLiteral(symbol) => {
                let arena = self
                    .arena_for_source(expression.source())?
                    .expect("resolved target requires arena");
                let symbol = arena.symbol(symbol).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "struct literal references an unknown symbol".into(),
                })?;
                if !matches!(
                    symbol.kind,
                    ResolvedSymbolKind::Struct | ResolvedSymbolKind::Event
                ) || symbol.name != name
                {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "struct literal `{name}` diverges from resolver symbol `{}`",
                            symbol.name
                        ),
                    });
                }
            }
            ResolvedTarget::ExternalStructLiteral => {
                if !self.structs.borrow().contains_key(name) {
                    return Err(SemanticError {
                        code: "E_UNEXPORTED_TYPE",
                        message: format!(
                            "struct type `{name}` is absent from the explicit package exports"
                        ),
                    });
                }
            }
            _ => {
                return Err(SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: format!(
                        "struct literal `{name}` carries a non-struct resolver target"
                    ),
                });
            }
        }
        Ok(())
    }
    fn validate_named_type_target(
        &self,
        node: Option<&crate::resolved::ResolvedNode>,
        name: &str,
    ) -> Result<(), SemanticError> {
        use crate::resolved::{ResolvedSymbolKind, ResolvedTarget, ResolvedTypeTarget};
        if self.event_names.borrow().contains(name) {
            return Err(SemanticError {
                code: "E_EVENT_VALUE",
                message: format!(
                    "event `{name}` is an emission declaration, not a value type; use `emit {name} {{ ... }};`"
                ),
            });
        }
        let Some(node) = node else {
            return Ok(());
        };
        let Some(target) = node.target.as_ref() else {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!("type `{name}` has no resolver-produced target"),
            });
        };
        let ResolvedTarget::Type(target) = target else {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!("named type `{name}` carries a non-type resolver target"),
            });
        };
        match target {
            ResolvedTypeTarget::Builtin if !V1_SOURCE_TYPE_NAMES.contains(&name) => {
                return Err(SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: format!("type `{name}` is not in the canonical V1 builtin type table"),
                });
            }
            ResolvedTypeTarget::Struct(symbol) | ResolvedTypeTarget::Enum(symbol) => {
                let expected_kind = if matches!(target, ResolvedTypeTarget::Enum(_)) {
                    ResolvedSymbolKind::Enum
                } else {
                    ResolvedSymbolKind::Struct
                };
                let arena = self
                    .arena_for_source(node.source)?
                    .expect("resolved type requires arena");
                let symbol = arena.symbol(*symbol).ok_or_else(|| SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: "type target references an unknown struct".into(),
                })?;
                if symbol.kind != expected_kind || symbol.name != name {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "type `{name}` diverges from resolver symbol `{}`",
                            symbol.name
                        ),
                    });
                }
            }
            ResolvedTypeTarget::ExternalStruct => {
                if !self.structs.borrow().contains_key(name)
                    && !self.error_types.borrow().contains_key(name)
                    && !self.enum_types.borrow().contains_key(name)
                    && !self.external_types.borrow().contains_key(name)
                {
                    return Err(SemanticError {
                        code: "E_INTERNAL_RESOLUTION",
                        message: format!(
                            "external type `{name}` is absent from the typed target interface"
                        ),
                    });
                }
            }
            ResolvedTypeTarget::ExternalType => {
                if !self.external_types.borrow().contains_key(name) {
                    return Err(SemanticError {
                        code: "E_UNEXPORTED_TYPE",
                        message: format!(
                            "type `{name}` is not exported by the locked import graph"
                        ),
                    });
                }
            }
            ResolvedTypeTarget::Builtin => {}
        }
        Ok(())
    }
    fn record_typed_hir_node(&self, expression: &Expr, ty: &Type) -> Result<(), SemanticError> {
        // Explicit annotations are checked while they are resolved, but an
        // inferred tuple or sum can also combine many references to the same
        // named product DAG. Enforce the identical expanded-shape budget at
        // the typed expression boundary before downstream ABI and lowering
        // walks can revisit that graph.
        validate_use_site_type_resolution_budget(self, ty)?;
        let Some(node) = self.resolved_node(
            expression.hir_id(),
            crate::resolved::ResolvedNodeKind::Expression,
            expression.source(),
        )?
        else {
            return Ok(());
        };
        let mut typed = self.typed_hir_nodes.borrow_mut();
        let arena = self
            .arena_for_source(expression.source())?
            .expect("resolved node requires arena");
        let id = TypedHirNodeId {
            source: arena.source(),
            local: node.id,
        };
        if let Some(previous) = typed.insert(id, ty.clone())
            && resolve_struct_type(&previous) != resolve_struct_type(ty)
        {
            return Err(SemanticError {
                code: "E_INTERNAL_RESOLUTION",
                message: format!(
                    "HIR node {} acquired inconsistent semantic types",
                    node.id.0
                ),
            });
        }
        Ok(())
    }
    fn capture_diagnostic(
        &self,
        primary: Option<crate::source::SourceRange>,
        fix: Option<crate::semantic_diagnostics::SemanticFix>,
    ) {
        let Some(primary) = primary else {
            return;
        };
        let mut pending = self.pending_diagnostic.borrow_mut();
        if pending.is_none() {
            *pending = Some(crate::semantic_diagnostics::SemanticDiagnostic::at(
                primary, fix,
            ));
        }
    }
    fn replace_diagnostic(
        &self,
        primary: Option<crate::source::SourceRange>,
        fix: Option<crate::semantic_diagnostics::SemanticFix>,
    ) {
        let Some(primary) = primary else {
            return;
        };
        self.pending_diagnostic
            .replace(Some(crate::semantic_diagnostics::SemanticDiagnostic::at(
                primary, fix,
            )));
    }
    /// Record structured metadata unless an inner failure already did.
    fn capture_structured(&self, diagnostic: crate::semantic_diagnostics::SemanticDiagnostic) {
        let mut pending = self.pending_diagnostic.borrow_mut();
        if pending.is_none() {
            *pending = Some(diagnostic);
        }
    }
    /// Record a primary range with site-specific help.
    fn capture_help(&self, primary: Option<crate::source::SourceRange>, help: String) {
        if let Some(primary) = primary {
            self.capture_structured(
                crate::semantic_diagnostics::SemanticDiagnostic::at(primary, None).with_help(help),
            );
        }
    }
    /// Label explaining how an unannotated local received its type.
    fn inferred_local_label(
        &self,
        name: &str,
        ty: &Type,
    ) -> Option<crate::semantic_diagnostics::SemanticDiagnosticLabel> {
        let source = self.inferred_locals.borrow().get(name).copied()?;
        Some(crate::semantic_diagnostics::SemanticDiagnosticLabel {
            source,
            message: format!(
                "`{name}` has no type annotation, so its type `{}` was inferred from this initializer",
                render_type_name(ty)
            ),
        })
    }
    fn capture_expression_diagnostic(
        &self,
        expression: &Expr,
        fix: Option<crate::semantic_diagnostics::SemanticFix>,
    ) {
        self.capture_diagnostic(self.expression_source(expression), fix);
    }
    fn capture_statement_diagnostic(
        &self,
        statement: &Statement,
        fix: Option<crate::semantic_diagnostics::SemanticFix>,
    ) {
        self.capture_diagnostic(self.statement_source(statement), fix);
    }
    fn take_diagnostic(&self) -> Option<crate::semantic_diagnostics::SemanticDiagnostic> {
        self.pending_diagnostic.borrow_mut().take()
    }
    fn discard_diagnostic(&self) {
        self.pending_diagnostic.borrow_mut().take();
    }
    fn fresh_aggregate_capture(&self) -> String {
        let index = self.next_synthetic_binding.get();
        self.next_synthetic_binding.set(
            index
                .checked_add(1)
                .expect("aggregate capture counter must not overflow"),
        );
        // NUL cannot occur in a source identifier, so this compiler-owned
        // binding cannot collide with a user local in any nested scope.
        format!("{AGGREGATE_CAPTURE_PREFIX}{index}")
    }
    /// Check whether one expression can initialize `expected` without letting a speculative error
    /// replace the diagnostic for the enclosing invalid construct. Typed expression analysis is
    /// otherwise side-effect free; a cloned local environment plus restored diagnostic/capacity
    /// scratch state makes this suitable for deciding whether a fix recipe will type-check.
    fn expression_is_assignable(
        &self,
        expression: &Expr,
        vars: &HashMap<String, Type>,
        expected: &Type,
    ) -> bool {
        let pending = self.pending_diagnostic.borrow_mut().take();
        let required_capacity = self.required_list_capacity.borrow_mut().take();
        let mut probe_vars = vars.clone();
        let result = analyze_expr_expected(self, expression, &mut probe_vars, Some(expected))
            .and_then(|mut value| ensure_assignable_and_coerce(expected, &mut value));
        self.pending_diagnostic.replace(pending);
        self.required_list_capacity.replace(required_capacity);
        result.is_ok()
    }
    fn declaration_diagnostic(
        &self,
        name: &str,
    ) -> Option<crate::semantic_diagnostics::SemanticDiagnostic> {
        self.resolved_declaration_sources
            .borrow()
            .get(name)
            .copied()
            .map(|primary| crate::semantic_diagnostics::SemanticDiagnostic::at(primary, None))
    }
    fn reset(&self) {
        self.structs.borrow_mut().clear();
        self.states.borrow_mut().clear();
        self.consts.borrow_mut().clear();
        self.function_returns.borrow_mut().clear();
        self.function_modifiers.borrow_mut().clear();
        self.permissions.borrow_mut().clear();
        self.function_params.borrow_mut().clear();
        self.function_summaries.borrow_mut().clear();
        self.global_declarations.borrow_mut().clear();
        self.current_function_modifiers.borrow_mut().take();
        self.current_function_name.borrow_mut().take();
        self.current_mutable_bindings.borrow_mut().clear();
        self.trigger_callback_functions.borrow_mut().clear();
        self.current_state_param_names.borrow_mut().clear();
        self.variant_codes.borrow_mut().clear();
        self.error_types.borrow_mut().clear();
        self.enum_types.borrow_mut().clear();
        self.event_names.borrow_mut().clear();
        self.contracts.borrow_mut().clear();
        self.external_functions.borrow_mut().clear();
        self.external_types.borrow_mut().clear();
        self.external_states.borrow_mut().clear();
        self.resolved_arenas.borrow_mut().clear();
        self.resolved_declaration_sources.borrow_mut().clear();
        self.resolved_binding_types.borrow_mut().clear();
        self.typed_hir_nodes.borrow_mut().clear();
        self.pending_diagnostic.borrow_mut().take();
        self.inferred_locals.borrow_mut().clear();
        self.current_return_source.borrow_mut().take();
        self.statement_recovery.set(false);
        self.recovered_failures.borrow_mut().clear();
        self.extra_failures.borrow_mut().clear();
        self.required_list_capacity.borrow_mut().take();
        self.resolved_named_types.borrow_mut().clear();
        self.resolved_named_type_resources.borrow_mut().clear();
        self.next_synthetic_binding.set(0);
    }
}
fn validate_declaration_uniqueness(program: &Program) -> Result<Vec<String>, SemanticError> {
    let mut functions = HashSet::new();
    let mut types = HashSet::new();
    let mut states = HashSet::new();
    let mut consts = HashSet::new();
    let mut triggers = HashSet::new();
    if program.unit.name == "kotodama" || is_reserved_source_type_declaration(&program.unit.name) {
        return Err(SemanticError {
            code: "E_RESERVED_DECLARATION",
            message: format!(
                "source unit `{}` uses a compiler-reserved name",
                program.unit.name
            ),
        });
    }
    let mut declarations = HashMap::from([(program.unit.name.clone(), "source unit")]);
    let mut struct_names = Vec::new();
    let mut register_declaration = |name: &str,
                                    kind: &'static str,
                                    is_function: bool,
                                    is_type: bool|
     -> Result<(), SemanticError> {
        let reserved = if is_type {
            is_reserved_source_type_declaration(name)
        } else {
            is_reserved_source_declaration(name, is_function)
        };
        if reserved {
            return Err(SemanticError {
                code: "E_RESERVED_DECLARATION",
                message: format!("{kind} `{name}` uses a compiler-reserved name"),
            });
        }
        if let Some(previous_kind) = declarations.insert(name.to_owned(), kind) {
            return Err(SemanticError {
                code: "E_DUPLICATE_DECLARATION",
                message: format!("declaration name `{name}` is already used by a {previous_kind}"),
            });
        }
        Ok(())
    };
    for directive in &program.directives {
        match &directive.kind {
            SourceDirectiveKind::ContractImport { alias, .. } => {
                register_declaration(alias, "contract import", false, true)?;
            }
            SourceDirectiveKind::ContractTypeImport { alias, .. } => {
                register_declaration(alias, "imported type", false, true)?;
            }
            _ => {}
        }
    }
    for permission in &program.permissions {
        register_declaration(&permission.name, "permission", false, false)?;
    }
    for item in &program.items {
        match item {
            Item::Function(function) => {
                if !functions.insert(function.name.as_str()) {
                    return Err(SemanticError {
                        code: "K2001",
                        message: format!("duplicate function `{}`", function.name),
                    });
                }
                register_declaration(&function.name, "function", true, false)?;
                let mut params = HashSet::new();
                for param in &function.params {
                    if !params.insert(param.name.as_str()) {
                        return Err(SemanticError {
                            code: "K2001",
                            message: format!(
                                "duplicate parameter `{}` in function `{}`",
                                param.name, function.name
                            ),
                        });
                    }
                }
            }
            Item::Struct(definition) | Item::Event(definition) => {
                if !types.insert(definition.name.as_str()) {
                    return Err(SemanticError {
                        code: "K2001",
                        message: format!("duplicate type `{}`", definition.name),
                    });
                }
                register_declaration(&definition.name, "type", false, true)?;
                let mut fields = HashSet::new();
                for (field, _) in &definition.fields {
                    if !fields.insert(field.as_str()) {
                        return Err(SemanticError {
                            code: "K2001",
                            message: format!(
                                "duplicate field `{field}` in type `{}`",
                                definition.name
                            ),
                        });
                    }
                }
                struct_names.push(definition.name.clone());
            }
            Item::Enum(definition) => {
                if !types.insert(definition.name.as_str()) {
                    return Err(SemanticError {
                        code: "K2001",
                        message: format!("duplicate type `{}`", definition.name),
                    });
                }
                register_declaration(&definition.name, "type", false, true)?;
                let mut variants = HashSet::new();
                let mut codes = HashSet::new();
                for variant in &definition.variants {
                    if !variants.insert(variant.name.as_str()) {
                        return Err(SemanticError {
                            code: "K2001",
                            message: format!(
                                "duplicate enum variant `{}::{}`",
                                definition.name, variant.name
                            ),
                        });
                    }
                    if !codes.insert(variant.code) {
                        return Err(SemanticError {
                            code: "K2001",
                            message: format!(
                                "duplicate enum code {} in `{}`",
                                variant.code, definition.name
                            ),
                        });
                    }
                }
            }
            Item::State(state) => {
                if !states.insert(state.name.as_str()) {
                    return Err(SemanticError {
                        code: "K2001",
                        message: format!("duplicate state `{}`", state.name),
                    });
                }
                register_declaration(&state.name, "state declaration", false, false)?;
            }
            Item::Const(constant) => {
                if !consts.insert(constant.name.as_str()) {
                    return Err(SemanticError {
                        code: "K2001",
                        message: format!("duplicate const `{}`", constant.name),
                    });
                }
                register_declaration(&constant.name, "const declaration", false, false)?;
            }
            Item::Trigger(trigger) => {
                if !triggers.insert(trigger.name.as_str()) {
                    return Err(SemanticError {
                        code: "K2001",
                        message: format!("duplicate trigger `{}`", trigger.name),
                    });
                }
                register_declaration(&trigger.name, "trigger declaration", false, false)?;
            }
        }
    }
    Ok(struct_names)
}
fn collect_struct_dependencies(
    ty: &Type,
    known_structs: &HashSet<String>,
    dependencies: &mut Vec<String>,
    seen: &mut HashSet<String>,
) {
    let mut pending = vec![ty];
    while let Some(current) = pending.pop() {
        match current {
            Type::NamedStruct(name) | Type::Struct { name, .. } => {
                if known_structs.contains(name) && seen.insert(name.clone()) {
                    dependencies.push(name.clone());
                }
            }
            Type::StateMap(key, value) => {
                pending.push(value);
                pending.push(key);
            }
            Type::Secret(inner) => pending.push(inner),
            Type::Option(inner) => pending.push(inner),
            Type::List(element, _) => pending.push(element),
            Type::Result(ok, err) => {
                pending.push(err);
                pending.push(ok);
            }
            Type::Tuple(items) => pending.extend(items.iter().rev()),
            Type::ContractRef(_)
            | Type::Int
            | Type::Decimal
            | Type::Quantity
            | Type::Bool
            | Type::String
            | Type::Bytes
            | Type::DataSpaceId
            | Type::AxtDescriptor
            | Type::AxtAnchoredSpendV1
            | Type::ProofBlob
            | Type::SoracloudRequest
            | Type::SoracloudResponse
            | Type::AccountId
            | Type::AssetDefinitionId
            | Type::AssetId
            | Type::NftId
            | Type::DomainId
            | Type::Name
            | Type::Json
            | Type::Unit
            | Type::StateCursor(_)
            | Type::Enum(_)
            | Type::ErrorEnum(_) => {}
        }
    }
}
fn value_struct_cycle(context: &SemanticContext, struct_names: &[String]) -> Option<Vec<String>> {
    let definitions = context.structs.borrow().clone();
    let known_structs = struct_names.iter().cloned().collect::<HashSet<_>>();
    let mut graph = HashMap::new();
    for name in struct_names {
        let mut dependencies = Vec::new();
        let mut seen = HashSet::new();
        if let Some(fields) = definitions.get(name) {
            for (_, ty) in fields {
                collect_struct_dependencies(ty, &known_structs, &mut dependencies, &mut seen);
            }
        }
        graph.insert(name.clone(), dependencies);
    }
    // Use an explicit DFS stack so malformed recursive value types cannot
    // overflow the compiler stack before they are rejected.
    let mut visit_state = struct_names
        .iter()
        .cloned()
        .map(|name| (name, 0_u8))
        .collect::<HashMap<_, _>>();
    for root in struct_names {
        if visit_state.get(root).copied().unwrap_or_default() != 0 {
            continue;
        }
        visit_state.insert(root.clone(), 1);
        let mut path = vec![root.clone()];
        let mut stack = vec![(root.clone(), 0_usize)];
        while !stack.is_empty() {
            let next_dependency = {
                let (current, next_index) = stack.last_mut().expect("stack is not empty");
                let dependencies = graph
                    .get(current)
                    .expect("every declared struct has a graph node");
                if let Some(dependency) = dependencies.get(*next_index) {
                    *next_index += 1;
                    Some(dependency.clone())
                } else {
                    None
                }
            };
            if let Some(dependency) = next_dependency {
                match visit_state.get(&dependency).copied().unwrap_or_default() {
                    0 => {
                        visit_state.insert(dependency.clone(), 1);
                        path.push(dependency.clone());
                        stack.push((dependency, 0));
                    }
                    1 => {
                        let cycle_start = path
                            .iter()
                            .position(|name| name == &dependency)
                            .expect("visiting structs are present in the active path");
                        let mut cycle = path[cycle_start..].to_vec();
                        cycle.push(dependency);
                        return Some(cycle);
                    }
                    _ => {}
                }
                continue;
            }
            let (finished, _) = stack.pop().expect("stack is not empty");
            let path_entry = path.pop().expect("active path mirrors DFS stack");
            debug_assert_eq!(finished, path_entry);
            visit_state.insert(finished, 2);
        }
    }
    None
}
fn value_struct_cycle_error(cycle: &[String]) -> SemanticError {
    SemanticError {
        code: "K2006",
        message: format!("cyclic value struct definition: {}", cycle.join(" -> ")),
    }
}
fn validate_acyclic_value_structs(
    context: &SemanticContext,
    struct_names: &[String],
) -> Result<(), SemanticError> {
    value_struct_cycle(context, struct_names)
        .map_or(Ok(()), |cycle| Err(value_struct_cycle_error(&cycle)))
}
#[derive(Clone, Copy, Debug, Default)]
struct ExpandedTypeResources {
    nodes: usize,
    depth: usize,
}
#[derive(Debug)]
struct StructResolutionBudgetError {
    owner: Option<String>,
    error: SemanticError,
}
struct StructResolutionPlan {
    order: Vec<String>,
    resources: HashMap<String, ExpandedTypeResources>,
}
fn capped_expanded_nodes(nodes: usize, additional: usize) -> usize {
    nodes
        .saturating_add(additional)
        .min(MAX_EXPANDED_TYPE_NODES.saturating_add(1))
}
/// Measure one type using already-memoized resources for every named dependency.
///
/// This walk is deliberately iterative. Named structs contribute their
/// memoized expanded shape without visiting it again, so a diamond-shaped DAG
/// takes time proportional to the source graph rather than its expanded tree.
fn measure_expanded_type(
    ty: &Type,
    named: &HashMap<String, ExpandedTypeResources>,
) -> ExpandedTypeResources {
    let mut resources = ExpandedTypeResources::default();
    let mut pending = vec![(ty, 1_usize)];
    while let Some((current, depth)) = pending.pop() {
        match current {
            Type::NamedStruct(name) => {
                let contribution = named
                    .get(name)
                    .copied()
                    .unwrap_or(ExpandedTypeResources { nodes: 1, depth: 1 });
                resources.nodes = capped_expanded_nodes(resources.nodes, contribution.nodes);
                resources.depth = resources
                    .depth
                    .max(depth.saturating_sub(1).saturating_add(contribution.depth));
            }
            Type::StateMap(key, value) | Type::Result(key, value) => {
                resources.nodes = capped_expanded_nodes(resources.nodes, 1);
                resources.depth = resources.depth.max(depth);
                pending.push((value, depth.saturating_add(1)));
                pending.push((key, depth.saturating_add(1)));
            }
            Type::Secret(inner) | Type::Option(inner) | Type::List(inner, _) => {
                resources.nodes = capped_expanded_nodes(resources.nodes, 1);
                resources.depth = resources.depth.max(depth);
                pending.push((inner, depth.saturating_add(1)));
            }
            Type::Tuple(items) => {
                resources.nodes = capped_expanded_nodes(resources.nodes, 1);
                resources.depth = resources.depth.max(depth);
                pending.extend(
                    items
                        .iter()
                        .rev()
                        .map(|item| (item, depth.saturating_add(1))),
                );
            }
            Type::Struct { name, fields } => {
                if let Some(contribution) = named.get(name) {
                    resources.nodes = capped_expanded_nodes(resources.nodes, contribution.nodes);
                    resources.depth = resources
                        .depth
                        .max(depth.saturating_sub(1).saturating_add(contribution.depth));
                    continue;
                }
                resources.nodes = capped_expanded_nodes(resources.nodes, 1);
                resources.depth = resources.depth.max(depth);
                pending.extend(
                    fields
                        .iter()
                        .rev()
                        .map(|(_, field)| (field, depth.saturating_add(1))),
                );
            }
            Type::ContractRef(_)
            | Type::Int
            | Type::Decimal
            | Type::Quantity
            | Type::Bool
            | Type::String
            | Type::Bytes
            | Type::DataSpaceId
            | Type::AxtDescriptor
            | Type::AxtAnchoredSpendV1
            | Type::ProofBlob
            | Type::SoracloudRequest
            | Type::SoracloudResponse
            | Type::AccountId
            | Type::AssetDefinitionId
            | Type::AssetId
            | Type::NftId
            | Type::DomainId
            | Type::Name
            | Type::Json
            | Type::Unit
            | Type::StateCursor(_)
            | Type::Enum(_)
            | Type::ErrorEnum(_) => {
                resources.nodes = capped_expanded_nodes(resources.nodes, 1);
                resources.depth = resources.depth.max(depth);
            }
        }
    }
    resources
}
/// Prove that materializing the acyclic named-type graph fits fixed V1 limits.
///
/// The dependency graph is processed leaf-first. Each named shape is measured once and memoized;
/// neither a deep chain nor an exponentially branching DAG is recursively expanded during this
/// proof. The existing materializer runs only after the proof, when its output depth and aggregate
/// allocation are known to be bounded.
fn validate_struct_resolution_budget(
    context: &SemanticContext,
    local_struct_names: &[String],
) -> Result<StructResolutionPlan, StructResolutionBudgetError> {
    let definitions = context.structs.borrow();
    let known_structs = definitions.keys().cloned().collect::<HashSet<_>>();
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    for (name, fields) in definitions.iter() {
        let mut dependencies = Vec::new();
        let mut seen = HashSet::new();
        for (_, ty) in fields {
            collect_struct_dependencies(ty, &known_structs, &mut dependencies, &mut seen);
        }
        dependencies.sort();
        graph.insert(name.clone(), dependencies);
    }
    let mut unresolved_dependencies = graph
        .iter()
        .map(|(name, dependencies)| (name.clone(), dependencies.len()))
        .collect::<HashMap<_, _>>();
    let mut dependents = HashMap::<String, Vec<String>>::new();
    for (owner, dependencies) in &graph {
        for dependency in dependencies {
            dependents
                .entry(dependency.clone())
                .or_default()
                .push(owner.clone());
        }
    }
    for owners in dependents.values_mut() {
        owners.sort();
    }
    let mut ready = unresolved_dependencies
        .iter()
        .filter_map(|(name, count)| (*count == 0).then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(graph.len());
    while let Some(name) = ready.pop_first() {
        order.push(name.clone());
        if let Some(owners) = dependents.get(&name) {
            for owner in owners {
                let Some(remaining) = unresolved_dependencies.get_mut(owner) else {
                    continue;
                };
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    ready.insert(owner.clone());
                }
            }
        }
    }
    if order.len() != graph.len() {
        return Err(StructResolutionBudgetError {
            owner: None,
            error: SemanticError {
                code: "K2006",
                message: "cyclic value struct definition reached named-type resolution".into(),
            },
        });
    }
    let mut measured = HashMap::<String, ExpandedTypeResources>::new();
    for name in &order {
        let mut resources = ExpandedTypeResources { nodes: 1, depth: 1 };
        if let Some(fields) = definitions.get(name) {
            for (_, field_ty) in fields {
                let field = measure_expanded_type(field_ty, &measured);
                resources.nodes = capped_expanded_nodes(resources.nodes, field.nodes);
                resources.depth = resources.depth.max(field.depth.saturating_add(1));
            }
        }
        measured.insert(name.clone(), resources);
    }
    let mut roots = local_struct_names.to_vec();
    roots.sort();
    for name in &roots {
        let resources = measured.get(name).copied().unwrap_or_default();
        if resources.depth > MAX_NESTING_DEPTH {
            return Err(StructResolutionBudgetError {
                owner: Some(name.clone()),
                error: SemanticError {
                    code: "K2008",
                    message: format!(
                        "expanded value type `{name}` exceeds the V1 nesting limit of {MAX_NESTING_DEPTH} levels"
                    ),
                },
            });
        }
        if resources.nodes > MAX_EXPANDED_TYPE_NODES {
            return Err(StructResolutionBudgetError {
                owner: Some(name.clone()),
                error: SemanticError {
                    code: "K2008",
                    message: format!(
                        "expanded value type `{name}` exceeds the V1 resource limit of {MAX_EXPANDED_TYPE_NODES} type nodes"
                    ),
                },
            });
        }
    }
    let total = roots.iter().fold(0_usize, |total, name| {
        capped_expanded_nodes(
            total,
            measured.get(name).map_or(0, |resources| resources.nodes),
        )
    });
    if total > MAX_EXPANDED_TYPE_NODES {
        return Err(StructResolutionBudgetError {
            owner: roots.first().cloned(),
            error: SemanticError {
                code: "K2008",
                message: format!(
                    "expanded value struct declarations exceed the V1 resource limit of {MAX_EXPANDED_TYPE_NODES} type nodes"
                ),
            },
        });
    }
    Ok(StructResolutionPlan {
        order,
        resources: measured,
    })
}
fn canonicalize_named_type(ty: &Type, resolved: &HashMap<String, Type>) -> Type {
    match ty {
        Type::NamedStruct(name) => resolved.get(name).cloned().unwrap_or_else(|| ty.clone()),
        Type::StateMap(key, value) => Type::StateMap(
            Box::new(canonicalize_named_type(key, resolved)),
            Box::new(canonicalize_named_type(value, resolved)),
        ),
        Type::Option(inner) => Type::Option(Box::new(canonicalize_named_type(inner, resolved))),
        Type::Result(ok, err) => Type::Result(
            Box::new(canonicalize_named_type(ok, resolved)),
            Box::new(canonicalize_named_type(err, resolved)),
        ),
        Type::List(element, capacity) => Type::List(
            Box::new(canonicalize_named_type(element, resolved)),
            *capacity,
        ),
        Type::Secret(inner) => Type::Secret(Box::new(canonicalize_named_type(inner, resolved))),
        Type::Tuple(items) => Type::Tuple(
            items
                .iter()
                .map(|item| canonicalize_named_type(item, resolved))
                .collect(),
        ),
        // Resolved product nodes are immutable and shared. Rewalking their
        // fields would turn a canonical DAG back into an expanded tree.
        Type::Struct { .. } => ty.clone(),
        _ => ty.clone(),
    }
}
fn install_canonical_struct_types(
    context: &SemanticContext,
    plan: StructResolutionPlan,
    program: &Program,
) {
    let own = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(definition) | Item::Event(definition) => Some(definition.name.as_str()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let prefix = match context.package_identity.borrow().as_deref() {
        Some(package) => format!("{package}::{}", program.unit.name),
        None => program.unit.name.clone(),
    };
    let StructResolutionPlan { order, resources } = plan;
    let definitions = context.structs.borrow().clone();
    let mut resolved = HashMap::<String, Type>::new();
    for name in order {
        let fields = definitions.get(&name).map_or_else(Vec::new, |fields| {
            fields
                .iter()
                .map(|(field, ty)| (field.clone(), canonicalize_named_type(ty, &resolved)))
                .collect()
        });
        resolved.insert(
            name.clone(),
            Type::Struct {
                name: if own.contains(name.as_str()) {
                    format!("{prefix}::{name}")
                } else {
                    context
                        .external_types
                        .borrow()
                        .get(&name)
                        .and_then(|ty| match ty {
                            Type::Struct { name, .. } => Some(name.clone()),
                            _ => None,
                        })
                        .unwrap_or(name)
                },
                fields: Arc::from(fields),
            },
        );
    }
    let struct_fields = resolved
        .iter()
        .filter_map(|(name, ty)| {
            let Type::Struct { fields, .. } = ty else {
                return None;
            };
            Some((name.clone(), fields.to_vec()))
        })
        .collect();
    context.structs.replace(struct_fields);
    context.resolved_named_types.replace(resolved);
    context.resolved_named_type_resources.replace(resources);
}
fn type_expr_mentions_name(ty: &TypeExpr, expected: &str) -> bool {
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        match ty.kind() {
            TypeExpr::Path(name) if name == expected => return true,
            TypeExpr::Generic { args, .. } | TypeExpr::Tuple(args) => {
                pending.extend(args.iter().rev());
            }
            TypeExpr::Path(_) | TypeExpr::Const(_) | TypeExpr::ConstExpression(_) => {}
            TypeExpr::Source { .. } | TypeExpr::Resolved { .. } => {
                unreachable!("kind() strips AST and resolved-HIR provenance wrappers")
            }
        }
    }
    false
}
fn recursive_function_call_cycle(context: &SemanticContext) -> Option<Vec<String>> {
    let summaries = context.function_summaries.borrow().clone();
    let mut function_names = summaries.keys().cloned().collect::<Vec<_>>();
    function_names.sort();
    let mut visit_state = function_names
        .iter()
        .cloned()
        .map(|name| (name, 0_u8))
        .collect::<HashMap<_, _>>();
    for root in &function_names {
        if visit_state.get(root).copied().unwrap_or_default() != 0 {
            continue;
        }
        visit_state.insert(root.clone(), 1);
        let mut path = vec![root.clone()];
        let mut stack = vec![(root.clone(), 0_usize)];
        while !stack.is_empty() {
            let next = {
                let (current, index) = stack.last_mut().expect("non-empty DFS stack");
                let calls = &summaries
                    .get(current)
                    .expect("declared function has a summary")
                    .calls;
                if let Some(callee) = calls.get_index(*index) {
                    *index += 1;
                    summaries.contains_key(callee).then(|| callee.clone())
                } else {
                    None
                }
            };
            if let Some(callee) = next {
                match visit_state.get(&callee).copied().unwrap_or_default() {
                    0 => {
                        visit_state.insert(callee.clone(), 1);
                        path.push(callee.clone());
                        stack.push((callee, 0));
                    }
                    1 => {
                        let start = path
                            .iter()
                            .position(|name| name == &callee)
                            .expect("active callee is present in DFS path");
                        let mut cycle = path[start..].to_vec();
                        cycle.push(callee);
                        return Some(cycle);
                    }
                    _ => {}
                }
                continue;
            }
            let (finished, _) = stack.pop().expect("non-empty DFS stack");
            path.pop().expect("DFS path mirrors stack");
            visit_state.insert(finished, 2);
        }
    }
    None
}
fn recursive_function_call_error(cycle: &[String]) -> SemanticError {
    SemanticError {
        code: "K2006",
        message: format!(
            "recursive function calls are not supported in Kotodama V1: {}",
            cycle.join(" -> ")
        ),
    }
}
fn validate_acyclic_function_calls(context: &SemanticContext) -> Result<(), SemanticError> {
    recursive_function_call_cycle(context)
        .map_or(Ok(()), |cycle| Err(recursive_function_call_error(&cycle)))
}
/// Analyze a parsed program in a fresh per-compilation semantic context.
pub fn analyze(program: &Program) -> Result<TypedProgram, SemanticError> {
    SemanticContext::new().analyze(program)
}
/// Diagnostic for a standalone test module reaching a production compilation.
const TEST_MODULE_PRODUCTION_MESSAGE: &str = "this file is a `koto_test` module; run it with `koto test`, which compiles it against its target in test mode (deployable builds never include test modules)";
/// Help for test code found in a deployable seiyaku.
const TEST_CODE_PRODUCTION_HELP: &str = "`koto check` and `koto build` reject test code instead of stripping it, so the artifact always matches the reviewed source. Move the tests into `<name>.test.ko` and run them with `koto test`.";
fn reject_test_surface_without_test_mode(
    context: &SemanticContext,
    program: &Program,
) -> Result<(), SemanticFailures> {
    if context.test_builtins_enabled {
        return Ok(());
    }
    let mut failures = Vec::new();
    let mut omitted = 0_usize;
    if program.test_target.is_some() {
        // A standalone test module is test code as a whole; one diagnostic says so instead of
        // one per test function.
        return Err(SemanticFailures {
            failures: vec![SemanticFailure {
                error: SemanticError {
                    code: "E_TEST_ONLY_PRODUCTION",
                    message: TEST_MODULE_PRODUCTION_MESSAGE.into(),
                },
                location: None,
                diagnostic: None,
            }],
        });
    }
    for fixture in &program.fixtures {
        record_semantic_failure(
            &mut failures,
            &mut omitted,
            SemanticFailure {
                error: SemanticError {
                    code: "E_TEST_ONLY_PRODUCTION",
                    message: format!(
                        "fixture `{}` belongs in a `*.test.ko` module that declares `koto_test {{ target: \"...\" }}`, not in a deployable seiyaku",
                        fixture.name
                    ),
                },
                location: None,
                diagnostic: None,
            },
        );
    }
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        if function.modifiers.is_test || function.modifiers.test_fixture.is_some() {
            record_semantic_failure(
                &mut failures,
                &mut omitted,
                SemanticFailure {
                    error: SemanticError {
                        code: "E_TEST_ONLY_PRODUCTION",
                        message: format!(
                            "test function `{}` belongs in a `*.test.ko` module that declares `koto_test {{ target: \"...\" }}`, not in a deployable seiyaku",
                            function.name
                        ),
                    },
                    location: Some(function.location),
                    diagnostic: context
                        .declaration_diagnostic(&function.name)
                        .map(|diagnostic| diagnostic.with_help(TEST_CODE_PRODUCTION_HELP)),
                },
            );
        }
    }
    if omitted != 0 {
        failures.push(SemanticFailure {
            error: SemanticError {
                code: "K0004",
                message: format!("{omitted} additional semantic error(s) were omitted"),
            },
            location: None,
            diagnostic: None,
        });
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(SemanticFailures { failures })
    }
}
/// Revalidate whole-program invariants after independently typed modules have
/// been linked into one HIR program.
///
/// Module analysis deliberately cannot trust an imported callee's body. This pass rebuilds the
/// complete call graph from final linked symbols, rejects cross-module recursion, and propagates
/// view/authorization effects through every linked helper before code generation.
pub fn validate_linked_program(
    program: &TypedProgram,
    zk_enabled: bool,
) -> Result<(), SemanticError> {
    crate::session::run_with_compiler_stack(move || {
        validate_linked_program_inline(program, zk_enabled)
    })
    .unwrap_or_else(|_| Err(compiler_worker_unavailable_semantic_error()))
}
fn validate_linked_program_inline(
    program: &TypedProgram,
    zk_enabled: bool,
) -> Result<(), SemanticError> {
    validate_enum_inventory(&program.enum_types)?;
    validate_event_inventory(&program.events)?;
    let context = SemanticContext::with_zk_enabled(zk_enabled);
    context.states.replace(
        program
            .states
            .iter()
            .map(|state| (state.name.clone(), state.ty.clone()))
            .collect(),
    );
    let mut returns = HashMap::new();
    for item in &program.items {
        let TypedItem::Function(function) = item;
        if returns
            .insert(
                function.name.clone(),
                function.ret_ty.clone().unwrap_or(Type::Unit),
            )
            .is_some()
        {
            return Err(SemanticError {
                code: "K2001",
                message: format!("duplicate linked function `{}`", function.name),
            });
        }
    }
    context.function_returns.replace(returns);
    for item in &program.items {
        let TypedItem::Function(function) = item;
        context.current_state_param_names.replace(
            function
                .param_types
                .iter()
                .filter(|param| param.is_state)
                .map(|param| param.name.clone())
                .collect(),
        );
        let summary = FunctionSummary {
            direct_effects: block_effects(&context, &function.body),
            calls: collect_called_functions(&context, &function.body),
            sites: effect_sites::effect_sites(&context, &function.body),
        };
        context
            .function_summaries
            .borrow_mut()
            .insert(function.name.clone(), summary);
    }
    context.current_state_param_names.borrow_mut().clear();
    validate_acyclic_function_calls(&context)?;
    validate_scalar_state_initialization(&context, &program.items, &program.states)?;
    crate::secret::validate_program(program, zk_enabled)?;
    effect_sites::enforce_permission_requirements(&context, &program.items)
        .map_err(SemanticFailures::into_first)
}
/// Derive the production HIR from a test-capable target without returning to AST.
///
/// Only declarations originating in the deployable target are supplied here; standalone test-module
/// HIR is linked into the suite separately. The projection removes inline `#[test]` functions,
/// proves that every retained call still resolves, rejects retained test-only builtins, and only
/// then clears test provenance.
pub(crate) fn project_test_target_to_production(
    mut target: TypedProgram,
    zk_enabled: bool,
) -> Result<TypedProgram, SemanticError> {
    let removed = target
        .items
        .iter()
        .filter_map(|item| {
            let TypedItem::Function(function) = item;
            function.modifiers.is_test.then(|| function.name.clone())
        })
        .collect::<HashSet<_>>();
    target.items.retain(|item| {
        let TypedItem::Function(function) = item;
        !function.modifiers.is_test
    });
    let retained = target
        .items
        .iter()
        .map(|item| {
            let TypedItem::Function(function) = item;
            function.name.clone()
        })
        .collect::<HashSet<_>>();
    for item in &target.items {
        let TypedItem::Function(function) = item;
        validate_production_projection_block(
            &function.body,
            &function.name,
            &retained,
            &removed,
            zk_enabled,
        )?;
    }
    target.test_support_enabled = false;
    validate_linked_program(&target, zk_enabled)?;
    Ok(target)
}
fn validate_production_projection_block(
    block: &TypedBlock,
    owner: &str,
    retained: &HashSet<String>,
    removed: &HashSet<String>,
    zk_enabled: bool,
) -> Result<(), SemanticError> {
    for statement in &block.statements {
        validate_production_projection_statement(statement, owner, retained, removed, zk_enabled)?;
    }
    if let Some(tail) = &block.tail {
        validate_production_projection_expr(tail, owner, retained, removed, zk_enabled)?;
    }
    Ok(())
}
fn validate_production_projection_statement(
    statement: &TypedStatement,
    owner: &str,
    retained: &HashSet<String>,
    removed: &HashSet<String>,
    zk_enabled: bool,
) -> Result<(), SemanticError> {
    match statement.kind() {
        TypedStatement::Let { value, .. } | TypedStatement::Expr(value) => {
            validate_production_projection_expr(value, owner, retained, removed, zk_enabled)
        }
        TypedStatement::Return(value) => {
            if let Some(value) = value {
                validate_production_projection_expr(value, owner, retained, removed, zk_enabled)?;
            }
            Ok(())
        }
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            validate_production_projection_expr(cond, owner, retained, removed, zk_enabled)?;
            validate_production_projection_block(
                then_branch,
                owner,
                retained,
                removed,
                zk_enabled,
            )?;
            if let Some(else_branch) = else_branch {
                validate_production_projection_block(
                    else_branch,
                    owner,
                    retained,
                    removed,
                    zk_enabled,
                )?;
            }
            Ok(())
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            validate_production_projection_expr(value, owner, retained, removed, zk_enabled)?;
            validate_production_projection_block(
                then_branch,
                owner,
                retained,
                removed,
                zk_enabled,
            )?;
            if let Some(else_branch) = else_branch {
                validate_production_projection_block(
                    else_branch,
                    owner,
                    retained,
                    removed,
                    zk_enabled,
                )?;
            }
            Ok(())
        }
        TypedStatement::While { cond, body } => {
            validate_production_projection_expr(cond, owner, retained, removed, zk_enabled)?;
            validate_production_projection_block(body, owner, retained, removed, zk_enabled)
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init) = init {
                validate_production_projection_statement(
                    init, owner, retained, removed, zk_enabled,
                )?;
            }
            if let Some(cond) = cond {
                validate_production_projection_expr(cond, owner, retained, removed, zk_enabled)?;
            }
            if let Some(step) = step {
                validate_production_projection_statement(
                    step, owner, retained, removed, zk_enabled,
                )?;
            }
            validate_production_projection_block(body, owner, retained, removed, zk_enabled)
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            validate_production_projection_expr(map, owner, retained, removed, zk_enabled)?;
            validate_production_projection_block(body, owner, retained, removed, zk_enabled)
        }
        TypedStatement::MapSet { map, key, value } => {
            validate_production_projection_expr(map, owner, retained, removed, zk_enabled)?;
            validate_production_projection_expr(key, owner, retained, removed, zk_enabled)?;
            validate_production_projection_expr(value, owner, retained, removed, zk_enabled)
        }
        TypedStatement::Break | TypedStatement::Continue => Ok(()),
    }
}
fn validate_production_projection_expr(
    expression: &TypedExpr,
    owner: &str,
    retained: &HashSet<String>,
    removed: &HashSet<String>,
    zk_enabled: bool,
) -> Result<(), SemanticError> {
    let recurse = |expression: &TypedExpr| {
        validate_production_projection_expr(expression, owner, retained, removed, zk_enabled)
    };
    match expression.kind() {
        ExprKind::Call { target: name, args }
        | ExprKind::NamedCall {
            target: name, args, ..
        } => {
            if let Some(builtin) = name.builtin() {
                match builtin.mode() {
                    BuiltinMode::TestOnly | BuiltinMode::TestFunctionOnly => {
                        return Err(SemanticError {
                            code: "E_TEST_ONLY_PRODUCTION",
                            message: format!(
                                "`{owner}` belongs to the deployable seiyaku, so it cannot call test-only builtin `{}`; call it from a `#[test] fn`, or move the helper into a `*.test.ko` module",
                                builtin.source_name()
                            ),
                        });
                    }
                    BuiltinMode::ZkOnly if !zk_enabled => {
                        return Err(SemanticError {
                            code: "E_ZK_MODE_REQUIRED",
                            message: format!(
                                "retained function `{owner}` calls ZK-only builtin `{}` without ZK build policy",
                                builtin.source_name()
                            ),
                        });
                    }
                    _ => {}
                }
            } else if name.user_name().is_some_and(|name| removed.contains(name)) {
                return Err(SemanticError {
                    code: "E_TEST_ONLY_PRODUCTION",
                    message: format!(
                        "`{owner}` belongs to the deployable seiyaku, so it cannot call test function `{name}`, which deployable builds omit"
                    ),
                });
            } else if name
                .user_name()
                .is_some_and(|name| !retained.contains(name))
            {
                return Err(SemanticError {
                    code: "K2002",
                    message: format!(
                        "linked function `{owner}` calls unknown function `{name}` after test projection"
                    ),
                });
            }
            for argument in args {
                recurse(argument)?;
            }
            Ok(())
        }
        ExprKind::Binary { left, right, .. }
        | ExprKind::Index {
            target: left,
            index: right,
        } => {
            recurse(left)?;
            recurse(right)
        }
        ExprKind::Unary { expr, .. }
        | ExprKind::NumericCast { expr }
        | ExprKind::NumericTryCast { expr }
        | ExprKind::Member { object: expr, .. }
        | ExprKind::OptionSome { value: expr }
        | ExprKind::ResultOk { value: expr }
        | ExprKind::ResultErr { error: expr }
        | ExprKind::Propagate { value: expr } => recurse(expr),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            recurse(cond)?;
            recurse(then_expr)?;
            recurse(else_expr)
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            recurse(condition)?;
            validate_production_projection_block(
                then_branch,
                owner,
                retained,
                removed,
                zk_enabled,
            )?;
            validate_production_projection_block(else_branch, owner, retained, removed, zk_enabled)
        }
        ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            recurse(value)?;
            validate_production_projection_block(
                then_branch,
                owner,
                retained,
                removed,
                zk_enabled,
            )?;
            validate_production_projection_block(else_branch, owner, retained, removed, zk_enabled)
        }
        ExprKind::Match { value, arms } => {
            recurse(value)?;
            for arm in arms {
                validate_production_projection_block(
                    &arm.body, owner, retained, removed, zk_enabled,
                )?;
            }
            Ok(())
        }
        ExprKind::Tuple(items) | ExprKind::List(items) | ExprKind::JsonArray(items) => {
            for item in items {
                recurse(item)?;
            }
            Ok(())
        }
        ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            recurse(source)?;
            recurse(expression)?;
            if let Some(condition) = condition {
                recurse(condition)?;
            }
            Ok(())
        }
        ExprKind::StructLiteral { fields, .. } | ExprKind::JsonObject(fields) => {
            for (_, value) in fields {
                recurse(value)?;
            }
            Ok(())
        }
        ExprKind::VariantCode(_)
        | ExprKind::IntLiteral(_)
        | ExprKind::DecimalLiteral { .. }
        | ExprKind::OptionNone
        | ExprKind::Bool(_)
        | ExprKind::String(_)
        | ExprKind::Bytes(_)
        | ExprKind::Ident(_) => Ok(()),
    }
}
fn register_event_names(context: &SemanticContext, program: &Program) -> Result<(), SemanticError> {
    let declared = program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Event(event) => Some(event.name.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if !declared.is_empty() && program.unit.kind != SourceUnitKind::Seiyaku {
        return Err(SemanticError {
            code: "E_EVENT_DECLARATION",
            message: "native events belong to their declaring seiyaku".into(),
        });
    }
    context.event_names.borrow_mut().extend(declared);
    Ok(())
}
fn declared_events(
    context: &SemanticContext,
) -> Result<Vec<iroha_data_model::smart_contract::event::ContractEventDescriptorV1>, SemanticError>
{
    let mut events = Vec::new();
    for name in context.event_names.borrow().iter() {
        let payload = resolve_struct_type_with_context(context, &Type::NamedStruct(name.clone()))?;
        let payload_type = crate::ir::entrypoint_return_schema(name, Some(&payload))
            .map_err(|message| SemanticError {
                code: "E_EVENT_SCHEMA",
                message,
            })?
            .expect("all public types have schemas");
        let descriptor = iroha_data_model::smart_contract::event::ContractEventDescriptorV1 {
            name: name.parse().map_err(|_| SemanticError {
                code: "E_EVENT_SCHEMA",
                message: format!("event `{name}` is not a canonical Name"),
            })?,
            payload_type,
        };
        if !descriptor.validate() {
            return Err(SemanticError {
                code: "E_EVENT_SCHEMA",
                message: format!(
                    "event `{name}` requires canonical public value fields; Json, StateCursor and private values cannot appear in its payload"
                ),
            });
        }
        events.push(descriptor);
    }
    validate_event_inventory(&events)?;
    Ok(events)
}
fn validate_event_inventory(
    events: &[iroha_data_model::smart_contract::event::ContractEventDescriptorV1],
) -> Result<(), SemanticError> {
    if !iroha_data_model::smart_contract::event::validate_contract_event_table(events) {
        return Err(SemanticError { code: "E_EVENT_SCHEMA", message: "native event declarations must be canonical, sorted and unique, with at most 256 events and 65536 encoded bytes".into() });
    }
    Ok(())
}

fn register_enum_types(context: &SemanticContext, program: &Program) -> Result<(), SemanticError> {
    let mut errors = context.error_types.borrow_mut();
    let mut enums = context.enum_types.borrow_mut();
    for descriptor in [
        ivm_abi::error_types::list_error_type(),
        ivm_abi::error_types::numeric_error_type(),
    ] {
        let name = descriptor
            .identity
            .rsplit("::")
            .next()
            .expect("builtin error name")
            .to_owned();
        errors.insert(name, Arc::new(descriptor));
    }
    for item in &program.items {
        let Item::Enum(definition) = item else {
            continue;
        };
        let identity = match context.package_identity.borrow().as_deref() {
            Some(package) => format!("{package}::{}::{}", program.unit.name, definition.name),
            None => format!("{}::{}", program.unit.name, definition.name),
        };
        match definition.kind {
            EnumKind::Data => {
                if definition
                    .variants
                    .iter()
                    .any(|variant| variant.message.is_some())
                {
                    return Err(sem_err(
                        "E_ENUM_MESSAGE",
                        "ordinary enum variants cannot declare error messages".into(),
                    ));
                }
                let mut variants = definition
                    .variants
                    .iter()
                    .map(|variant| ContractEnumVariantDescriptorV1 {
                        name: variant.name.clone(),
                        code: variant.code,
                    })
                    .collect::<Vec<_>>();
                variants.sort_by_key(|variant| variant.code);
                let descriptor = ContractEnumTypeDescriptorV1 { identity, variants };
                if !descriptor.validate() {
                    return Err(sem_err(
                        "E_ENUM_SCHEMA",
                        format!(
                            "enum `{}` requires unique names and nonzero u32 codes, with at most 256 variants",
                            definition.name
                        ),
                    ));
                }
                enums.insert(definition.name.clone(), Arc::new(descriptor));
            }
            EnumKind::Error => {
                if definition.variants.iter().any(|variant| {
                    variant
                        .message
                        .as_ref()
                        .is_some_and(|message| message.trim().is_empty() || message.len() > 4096)
                }) {
                    return Err(sem_err(
                        "E_ERROR_MESSAGE",
                        "error messages must contain nonblank text and at most 4096 UTF-8 bytes"
                            .into(),
                    ));
                }
                let mut variants = definition
                    .variants
                    .iter()
                    .map(|variant| ContractErrorVariantDescriptor {
                        name: variant.name.clone(),
                        code: variant.code,
                    })
                    .collect::<Vec<_>>();
                variants.sort_by_key(|variant| variant.code);
                let descriptor = ContractErrorTypeDescriptor { identity, variants };
                if !descriptor.validate() {
                    return Err(sem_err(
                        "E_ERROR_SCHEMA",
                        format!(
                            "error enum `{}` requires unique names and nonzero u32 codes, with at most 256 variants",
                            definition.name
                        ),
                    ));
                }
                errors.insert(definition.name.clone(), Arc::new(descriptor));
            }
        }
    }
    let mut codes = context.variant_codes.borrow_mut();
    for (name, descriptor) in errors.iter() {
        for variant in &descriptor.variants {
            codes.insert(format!("{name}::{}", variant.name), variant.code);
        }
    }
    for (name, descriptor) in enums.iter() {
        for variant in &descriptor.variants {
            codes.insert(format!("{name}::{}", variant.name), variant.code);
        }
    }
    Ok(())
}
fn validate_enum_inventory(types: &[ContractEnumTypeDescriptorV1]) -> Result<(), SemanticError> {
    if !iroha_data_model::smart_contract::manifest::validate_contract_enum_table(types) {
        return Err(sem_err("E_ENUM_SCHEMA", "ordinary enum inventory must contain at most 256 unique sorted types and fit 65536 canonical bytes".into()));
    }
    Ok(())
}
fn declared_enum_type(context: &SemanticContext, name: &str) -> Option<Type> {
    context
        .enum_types
        .borrow()
        .get(name)
        .map(|descriptor| Type::Enum(Arc::clone(descriptor)))
        .or_else(|| {
            context
                .error_types
                .borrow()
                .get(name)
                .map(|descriptor| Type::ErrorEnum(Arc::clone(descriptor)))
        })
}
fn nominal_variant_code(ty: &Type, name: &str) -> Option<u32> {
    match ty {
        Type::Enum(descriptor) => descriptor
            .variants
            .iter()
            .find(|variant| variant.name == name)
            .map(|variant| variant.code),
        Type::ErrorEnum(descriptor) => descriptor
            .variants
            .iter()
            .find(|variant| variant.name == name)
            .map(|variant| variant.code),
        _ => None,
    }
}
fn typed_variant_value(
    context: &SemanticContext,
    name: &str,
    code: u32,
) -> Result<TypedExpr, SemanticError> {
    let (namespace, variant) = name.rsplit_once("::").ok_or_else(|| {
        sem_err(
            "E_INTERNAL_RESOLUTION",
            format!("variant `{name}` has no nominal namespace"),
        )
    })?;
    let ty = declared_enum_type(context, namespace).ok_or_else(|| {
        sem_err(
            "E_INTERNAL_RESOLUTION",
            format!("variant `{name}` has no resolved nominal type"),
        )
    })?;
    if nominal_variant_code(&ty, variant) != Some(code) {
        return Err(sem_err(
            "E_INTERNAL_RESOLUTION",
            format!("variant code {code} is absent from `{namespace}`"),
        ));
    }
    Ok(TypedExpr {
        expr: ExprKind::VariantCode(code),
        ty,
    })
}

fn predeclare_integer_constants(
    context: &SemanticContext,
    program: &Program,
) -> Result<(), SemanticError> {
    let mut values = context.consts.borrow().clone();
    for item in &program.items {
        let Item::Const(declaration) = item else {
            continue;
        };
        if !matches!(declaration.ty.as_ref().map(TypeExpr::kind), Some(TypeExpr::Path(name)) if name == "int")
        {
            continue;
        }
        let mut value = analyze_const_expr(context, &declaration.value, &values, Some(&Type::Int))?;
        ensure_assignable_and_coerce(&Type::Int, &mut value)?;
        values.insert(declaration.name.clone(), fold_constant_numeric(&value)?);
    }
    context.consts.replace(values);
    Ok(())
}
fn evaluate_constant_declarations<'declaration>(
    context: &SemanticContext,
    declarations: impl IntoIterator<Item = &'declaration ConstDecl>,
    initial: IndexMap<String, TypedExpr>,
) -> Result<IndexMap<String, TypedExpr>, SemanticFailures> {
    let mut resolved_consts = initial;
    for decl in declarations {
        context.discard_diagnostic();
        let declared = decl.ty.as_ref().ok_or_else(|| SemanticError {
            code: "K2003",
            message: format!("const `{}` requires an explicit type", decl.name),
        })?;
        let expected =
            resolve_struct_type_with_context(context, &convert_type_expr(context, declared)?)
                .inspect_err(|_| context.capture_diagnostic(context.type_source(declared), None))?;

        let mut value =
            match analyze_const_expr(context, &decl.value, &resolved_consts, Some(&expected)) {
                Ok(value) => value,
                Err(error) => {
                    return Err(SemanticFailures {
                        failures: vec![SemanticFailure {
                            error,
                            location: None,
                            diagnostic: context.take_diagnostic(),
                        }],
                    });
                }
            };
        ensure_assignable_and_coerce(&expected, &mut value)?;
        if is_numeric_type(&value.ty) {
            value = fold_constant_numeric(&value)?;
        }
        resolved_consts.insert(decl.name.clone(), value);
    }
    Ok(resolved_consts)
}
fn register_permissions(
    context: &SemanticContext,
    program: &Program,
) -> Result<Vec<ContractPermissionDescriptorV1>, SemanticError> {
    let mut permissions = BTreeMap::new();
    for declaration in &program.permissions {
        if program.unit.kind == SourceUnitKind::Module
            || declaration.name == "anyone"
            || !iroha_data_model::smart_contract::entrypoint::is_canonical_kotodama_identifier(
                &declaration.name,
            )
        {
            return Err(sem_err(
                "E_PERMISSION_DECLARATION",
                "permissions must be named declarations in a seiyaku".into(),
            ));
        }
        let name = declaration.name.parse::<Name>().map_err(|error| {
            sem_err(
                "E_PERMISSION_DECLARATION",
                format!("invalid permission name: {error}"),
            )
        })?;
        let scope = match &declaration.chain_permission {
            Some(chain) => ContractPermissionScopeV1::Chain {
                permission_name: chain.parse::<Name>().map_err(|error| {
                    sem_err(
                        "E_PERMISSION_DECLARATION",
                        format!("invalid chain permission name: {error}"),
                    )
                })?,
            },
            None => ContractPermissionScopeV1::Instance,
        };
        if permissions.insert(name, scope).is_some() {
            return Err(sem_err(
                "E_DUPLICATE_DECLARATION",
                format!("duplicate permission `{}`", declaration.name),
            ));
        }
    }
    for item in &program.items {
        let Item::Function(function) = item else {
            continue;
        };
        if matches!(
            function.modifiers.kind,
            FunctionKind::Hajimari | FunctionKind::Kaizen
        ) {
            // Lifecycle policy is checked by analyze_function before caller
            // authorization names are meaningful for this declaration.
            continue;
        }
        if let Some(name) = function.modifiers.authorization.as_deref()
            && name != "anyone"
            && !name
                .parse::<Name>()
                .is_ok_and(|name| permissions.contains_key(&name))
        {
            return Err(sem_err(
                "E_UNKNOWN_PERMISSION",
                format!("authorization references undeclared permission `{name}`"),
            ));
        }
    }
    context.permissions.replace(
        permissions
            .iter()
            .map(|(name, scope)| (name.to_string(), scope.clone()))
            .collect(),
    );
    Ok(permissions
        .into_iter()
        .map(|(name, scope)| ContractPermissionDescriptorV1 { name, scope })
        .collect())
}

fn analyze_with_context(
    context: &SemanticContext,
    program: &Program,
) -> Result<TypedProgram, SemanticFailures> {
    reject_test_surface_without_test_mode(context, program)?;
    let imported =
        contract_imports::namespace_types(&context.contracts.borrow(), &program.directives)?;
    let mut external = context.external_types.borrow().clone();
    for (name, ty) in imported {
        if external.get(&name).is_some_and(|previous| previous != &ty) {
            return Err(sem_err(
                "E_DUPLICATE_DECLARATION",
                format!("imported type `{name}` has conflicting bindings"),
            )
            .into());
        }
        external.insert(name, ty);
    }
    context.install_external_types(&external);

    register_enum_types(context, program)?;
    register_event_names(context, program)?;
    let permissions = register_permissions(context, program)?;
    let external_structs = context.structs.borrow().clone();
    let external_consts = context.consts.borrow().clone();
    let external_variant_codes = context.variant_codes.borrow().clone();
    // Collect definitions up front so source order does not affect name resolution.
    let mut structs = external_structs.clone();
    let mut state_decls: Vec<(String, TypeExpr)> = Vec::new();
    let mut const_decls: Vec<ConstDecl> = Vec::new();
    let mut fn_returns: HashMap<String, Type> = HashMap::new();
    let mut fn_return_sources = HashMap::new();
    let mut fn_modifiers = context
        .external_functions
        .borrow()
        .iter()
        .map(|(name, signature)| (name.clone(), signature.modifiers.clone()))
        .collect::<HashMap<_, _>>();
    let mut trigger_callbacks: HashSet<String> = HashSet::new();
    let mut variant_codes = external_variant_codes;
    let struct_names = validate_declaration_uniqueness(program)?;
    predeclare_integer_constants(context, program)?;
    let mut global_declarations = std::iter::once(program.unit.name.clone())
        .chain(program.items.iter().map(|item| match item {
            Item::Function(function) => function.name.clone(),
            Item::Struct(definition) | Item::Event(definition) => definition.name.clone(),
            Item::Enum(definition) => definition.name.clone(),
            Item::Const(constant) => constant.name.clone(),
            Item::State(state) => state.name.clone(),
            Item::Trigger(trigger) => trigger.name.clone(),
        }))
        .collect::<HashSet<_>>();
    global_declarations.extend(
        program
            .permissions
            .iter()
            .map(|permission| permission.name.clone()),
    );
    global_declarations.extend(context.external_functions.borrow().keys().cloned());
    global_declarations.extend(context.external_states.borrow().keys().cloned());
    global_declarations.extend(external_structs.keys().cloned());
    global_declarations.extend(external_consts.keys().cloned());
    context.global_declarations.replace(global_declarations);
    let mut known_structs = external_structs;
    known_structs.extend(struct_names.iter().cloned().map(|name| (name, Vec::new())));
    context.structs.replace(known_structs);
    for item in &program.items {
        match item {
            Item::Struct(def) | Item::Event(def) => {
                let mut fields = Vec::new();
                for (name, ty_expr) in &def.fields {
                    fields.push((name.clone(), convert_type_expr(context, ty_expr)?));
                }
                structs.insert(def.name.clone(), fields);
            }
            Item::Enum(definition) => {
                for variant in &definition.variants {
                    variant_codes.insert(
                        format!("{}::{}", definition.name, variant.name),
                        variant.code,
                    );
                }
            }
            Item::State(st) => {
                state_decls.push((st.name.clone(), st.ty.clone()));
            }
            Item::Const(decl) => {
                const_decls.push(decl.clone());
            }
            Item::Function(f) => {
                let ret = if let Some(ret_ty) = &f.ret_ty {
                    fn_return_sources.insert(f.name.clone(), context.type_source(ret_ty));
                    convert_type_expr(context, ret_ty)?
                } else {
                    Type::Unit
                };
                fn_returns.insert(f.name.clone(), ret);
                fn_modifiers.insert(f.name.clone(), f.modifiers.clone());
            }
            Item::Trigger(trigger) => {
                trigger_callbacks.insert(trigger.call.entrypoint.clone());
            }
        }
    }
    context.structs.replace(structs);
    context.variant_codes.replace(variant_codes);
    if let Some(cycle) = value_struct_cycle(context, &struct_names) {
        if let [owner, dependency, ..] = cycle.as_slice()
            && let Some(ty) = program.items.iter().find_map(|item| {
                let (Item::Struct(definition) | Item::Event(definition)) = item else {
                    return None;
                };
                (definition.name == *owner).then(|| {
                    definition
                        .fields
                        .iter()
                        .map(|(_, ty)| ty)
                        .find(|ty| type_expr_mentions_name(ty, dependency))
                })?
            })
        {
            context.capture_diagnostic(context.type_source(ty), None);
        }
        return Err(value_struct_cycle_error(&cycle).into());
    }
    let resolution_plan = match validate_struct_resolution_budget(context, &struct_names) {
        Ok(plan) => plan,
        Err(failure) => {
            if let Some(owner) = failure.owner.as_deref()
                && let Some(ty) = program
                    .items
                    .iter()
                    .find_map(|item| {
                        let Item::Function(function) = item else {
                            return None;
                        };
                        function
                            .params
                            .iter()
                            .filter_map(|param| param.ty.as_ref())
                            .chain(function.ret_ty.iter())
                            .find(|ty| type_expr_mentions_name(ty, owner))
                    })
                    .or_else(|| {
                        program.items.iter().find_map(|item| {
                            let (Item::Struct(definition) | Item::Event(definition)) = item else {
                                return None;
                            };
                            if definition.name == owner {
                                definition.fields.first().map(|(_, ty)| ty)
                            } else {
                                None
                            }
                        })
                    })
            {
                context.capture_diagnostic(context.type_source(ty), None);
            }
            return Err(failure.error.into());
        }
    };
    install_canonical_struct_types(context, resolution_plan, program);
    let events = declared_events(context)?;

    let mut fn_returns = fn_returns
        .into_iter()
        .map(|(name, ty)| {
            let ty = resolve_struct_type_with_context(context, &ty).inspect_err(|_| {
                context.capture_diagnostic(fn_return_sources.get(&name).copied().flatten(), None);
            })?;
            Ok((name, ty))
        })
        .collect::<Result<HashMap<_, _>, SemanticError>>()?;
    for (name, signature) in context.external_functions.borrow().iter() {
        if fn_returns
            .insert(name.clone(), signature.return_type.clone())
            .is_some()
        {
            return Err(SemanticError {
                code: "E_DUPLICATE_DECLARATION",
                message: format!("imported function `{name}` collides with a local function"),
            }
            .into());
        }
    }
    let resolved_consts = evaluate_constant_declarations(context, &const_decls, external_consts)?;
    context.consts.replace(resolved_consts);
    let mut state: IndexMap<String, Type> = IndexMap::new();
    for (name, ty_expr) in state_decls {
        let ty = resolve_struct_type_with_context(context, &convert_type_expr(context, &ty_expr)?)
            .inspect_err(|_| context.capture_diagnostic(context.type_source(&ty_expr), None))?;

        if let Err(error) = validate_state_type(&ty) {
            context.capture_diagnostic(context.type_source(&ty_expr), None);
            return Err(error.into());
        }
        state.insert(name, ty);
    }
    let resolved_state: IndexMap<String, Type> = state
        .into_iter()
        .map(|(name, ty)| Ok((name, resolve_struct_type_with_context(context, &ty)?)))
        .collect::<Result<_, SemanticError>>()?;
    let mut all_states = context.external_states.borrow().clone();
    for (name, ty) in &resolved_state {
        if all_states.insert(name.clone(), ty.clone()).is_some() {
            return Err(SemanticError {
                code: "K2005",
                message: format!("target state `{name}` collides with a local state declaration"),
            }
            .into());
        }
    }
    context.states.replace(all_states);
    context.function_returns.replace(fn_returns);
    context.function_modifiers.replace(fn_modifiers.clone());
    context
        .trigger_callback_functions
        .replace(trigger_callbacks);
    let mut fn_params = context
        .external_functions
        .borrow()
        .iter()
        .map(|(name, signature)| (name.clone(), signature.params.clone()))
        .collect::<HashMap<_, _>>();
    for item in &program.items {
        let Item::Function(f) = item else { continue };
        let mut params = Vec::with_capacity(f.params.len());
        for param in &f.params {
            params.push(parse_declared_param_type(context, param, &f.modifiers)?);
        }
        fn_params.insert(f.name.clone(), params);
    }
    context.function_params.replace(fn_params);
    let mut items = Vec::new();
    let states = resolved_state
        .iter()
        .map(|(name, ty)| TypedStateDecl {
            name: name.clone(),
            ty: ty.clone(),
            source: None,
        })
        .collect::<Vec<_>>();
    let mut triggers = Vec::new();
    let mut trigger_names: HashSet<String> = HashSet::new();
    let mut failures = Vec::new();
    let mut omitted_failures = 0_usize;
    for item in &program.items {
        match item {
            Item::Function(f) => match analyze_function(context, f) {
                Ok(function) => {
                    context.discard_diagnostic();
                    context.required_list_capacity.borrow_mut().take();
                    items.push(TypedItem::Function(function));
                }
                Err(error) => {
                    record_semantic_failure(
                        &mut failures,
                        &mut omitted_failures,
                        SemanticFailure {
                            error,
                            location: Some(f.location),
                            diagnostic: context
                                .take_diagnostic()
                                .or_else(|| context.declaration_diagnostic(&f.name)),
                        },
                    );
                    let extra = std::mem::take(&mut *context.extra_failures.borrow_mut());
                    for (error, diagnostic) in extra {
                        record_semantic_failure(
                            &mut failures,
                            &mut omitted_failures,
                            SemanticFailure {
                                error,
                                location: Some(f.location),
                                diagnostic,
                            },
                        );
                    }
                }
            },
            Item::Trigger(trigger) => {
                if !trigger_names.insert(trigger.name.clone()) {
                    record_semantic_failure(
                        &mut failures,
                        &mut omitted_failures,
                        SemanticFailure {
                            error: SemanticError {
                                code: "K2001",
                                message: format!("duplicate trigger `{}`", trigger.name),
                            },
                            location: Some(trigger.location),
                            diagnostic: context.declaration_diagnostic(&trigger.name),
                        },
                    );
                    continue;
                }
                match analyze_trigger(context, trigger) {
                    Ok(trigger) => triggers.push(trigger),
                    Err(error) => record_semantic_failure(
                        &mut failures,
                        &mut omitted_failures,
                        SemanticFailure {
                            error,
                            location: Some(trigger.location),
                            diagnostic: context
                                .take_diagnostic()
                                .or_else(|| context.declaration_diagnostic(&trigger.name)),
                        },
                    ),
                }
            }
            Item::Struct(_) | Item::Event(_) | Item::Enum(_) | Item::Const(_) | Item::State(_) => {}
        }
    }
    if omitted_failures != 0 {
        failures.push(SemanticFailure {
            error: SemanticError {
                code: "K0004",
                message: format!("{omitted_failures} additional semantic error(s) were omitted"),
            },
            location: None,
            diagnostic: None,
        });
    }
    if !failures.is_empty() {
        return Err(SemanticFailures { failures });
    }
    if let Some(cycle) = recursive_function_call_cycle(context) {
        let location = cycle.first().and_then(|name| {
            program.items.iter().find_map(|item| {
                let Item::Function(function) = item else {
                    return None;
                };
                (&function.name == name).then_some(function.location)
            })
        });
        return Err(SemanticFailures {
            failures: vec![SemanticFailure {
                error: recursive_function_call_error(&cycle),
                location,
                diagnostic: cycle
                    .first()
                    .and_then(|name| context.declaration_diagnostic(name)),
            }],
        });
    }
    validate_scalar_state_initialization(context, &items, &states)?;
    let arenas = context.resolved_arenas.borrow();
    let hir_nodes = context
        .typed_hir_nodes
        .borrow()
        .iter()
        .filter_map(|(id, ty)| {
            let node = arenas.get(&id.source)?.node(id.local)?;
            Some((
                *id,
                TypedHirNode {
                    id: *id,
                    source: node.source,
                    target: node.target,
                    ty: ty.clone(),
                },
            ))
        })
        .collect();
    drop(arenas);
    let typed_program = TypedProgram {
        unit: program.unit.clone(),
        items,
        permissions,
        events,
        states,
        error_types: context
            .error_types
            .borrow()
            .values()
            .map(|descriptor| descriptor.as_ref().clone())
            .collect(),
        enum_types: context
            .enum_types
            .borrow()
            .values()
            .map(|descriptor| (descriptor.identity.clone(), descriptor.as_ref().clone()))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect(),
        error_messages: declared_error_messages(context, program),
        triggers,
        message_entries: Vec::new(),
        hir_nodes,
        source_files: BTreeMap::new(),
        test_support_enabled: context.test_builtins_enabled,
    };
    validate_enum_inventory(&typed_program.enum_types)?;
    validate_event_inventory(&typed_program.events)?;
    crate::secret::validate_program(&typed_program, context.zk_enabled)?;
    effect_sites::enforce_permission_requirements(context, &typed_program.items)?;
    Ok(typed_program)
}

fn declared_error_messages(
    context: &SemanticContext,
    program: &Program,
) -> Vec<ContractErrorMessage> {
    let descriptors = context.error_types.borrow();
    let mut messages = Vec::new();
    for item in &program.items {
        let Item::Enum(definition) = item else {
            continue;
        };
        let Some(descriptor) = descriptors.get(&definition.name) else {
            continue;
        };
        for variant in &definition.variants {
            if let Some(message) = &variant.message {
                messages.push(ContractErrorMessage {
                    error_type: descriptor.identity.clone(),
                    code: variant.code,
                    message: message.clone(),
                });
            }
        }
    }
    messages
        .sort_by(|left, right| (&left.error_type, left.code).cmp(&(&right.error_type, right.code)));
    messages
}
const JSON_LITERAL_REQUIRED_MESSAGE: &str =
    "Json::parse requires a direct string literal so native JSON is validated at compile time";
fn parse_json_literal(raw: &str) -> Result<json::Value, SemanticError> {
    json::parse_value(raw).map_err(|error| match error {
        json::Error::DuplicateField { field } => SemanticError {
            code: "E_JSON_DUPLICATE_KEY",
            message: format!(
                "Json::parse object key `{field}` is supplied more than once after string decoding"
            ),
        },
        error => SemanticError {
            code: "E_JSON_LITERAL_INVALID",
            message: format!("invalid Json::parse literal: {error}"),
        },
    })
}
fn json_from_expr(expr: &Expr) -> Result<Json, SemanticError> {
    let value = match expr {
        Expr::Source { expression, .. } | Expr::Resolved { expression, .. } => {
            return json_from_expr(expression);
        }
        Expr::String(s) => json::Value::String(s.clone()),
        Expr::IntLiteral(value) => {
            let number = value
                .try_to_i64()
                .map(JsonNumber::I64)
                .or_else(|| value.try_to_u64().map(JsonNumber::U64))
                .or_else(|| value.try_to_u128().map(JsonNumber::U128))
                .ok_or_else(|| SemanticError {
                code: "E_TRIGGER_METADATA_VALUE",
                message: "trigger metadata JSON cannot represent this int exactly; use an explicit string or typed state value"
                    .into(),
            })?;
            json::Value::Number(number)
        }
        Expr::DecimalLiteral(_) => {
            return Err(SemanticError {
                code: "E_TRIGGER_METADATA_VALUE",
                message: "quantity trigger metadata requires explicit native JSON construction"
                    .into(),
            });
        }
        Expr::Bool(b) => json::Value::Bool(*b),
        Expr::Ident(ident) if ident == "null" => json::Value::Null,
        Expr::Call {
            name,
            args,
            argument_names,
            implicit_receiver,
        } if name == "Json::parse" => {
            if *implicit_receiver {
                return Err(SemanticError {
                    code: "E_MALFORMED_CALL",
                    message: "Json::parse is a static constructor and has no receiver".into(),
                });
            }
            let builtin = Builtin::PointerConstructor(PointerConstructor::Json);
            let signature = builtin.signature();
            let parameter_names = signature
                .parameter_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>();
            let required = signature
                .parameters
                .iter()
                .map(|parameter| !parameter.ends_with('?'))
                .collect::<Vec<_>>();
            let plan = reorder_builtin_call_arguments(
                builtin,
                name,
                args,
                argument_names.as_deref(),
                false,
                &parameter_names,
                &required,
            )?;
            if plan.ordered.len() != 1 {
                return Err(SemanticError {
                    code: "K2003",
                    message: "Json::parse expects one argument".into(),
                });
            }
            let Expr::String(raw) = plan.ordered[0].kind() else {
                return Err(SemanticError {
                    code: "E_JSON_LITERAL_REQUIRED",
                    message: JSON_LITERAL_REQUIRED_MESSAGE.into(),
                });
            };
            parse_json_literal(raw)?
        }
        Expr::Call { name, .. } if name == "json" => {
            return Err(SemanticError {
                code: "E_NON_CANONICAL_BUILTIN",
                message: "legacy or non-canonical builtin spelling `json` is not supported; use `Json::parse`"
                    .into(),
            });
        }
        _ => {
            return Err(SemanticError {
                code: "E_TRIGGER_METADATA_VALUE",
                message: "trigger metadata values must be JSON literals".into(),
            });
        }
    };
    Json::from_norito_value_ref(&value).map_err(|err| SemanticError {
        code: "E_TRIGGER_METADATA_VALUE",
        message: format!("invalid trigger metadata value: {err}"),
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NumericKind {
    Int,
    Decimal,
    Quantity,
}
fn numeric_kind(ty: &Type) -> Option<NumericKind> {
    match resolve_struct_type(ty) {
        Type::Int => Some(NumericKind::Int),
        Type::Decimal => Some(NumericKind::Decimal),
        Type::Quantity => Some(NumericKind::Quantity),
        _ => None,
    }
}
fn numeric_kind_to_type(kind: NumericKind) -> Type {
    match kind {
        NumericKind::Int => Type::Int,
        NumericKind::Decimal => Type::Decimal,
        NumericKind::Quantity => Type::Quantity,
    }
}
fn typed_int_literal(value: &BigInt) -> Result<TypedExpr, SemanticError> {
    if value.to_twos_bytes().len() > MAX_MANTISSA_BYTES {
        return Err(SemanticError {
            code: "E_INT_LITERAL_OVERFLOW",
            message: "integer literal is outside the signed 512-bit Kotodama int domain".into(),
        });
    }
    Ok(TypedExpr {
        expr: ExprKind::IntLiteral(value.clone()),
        ty: Type::Int,
    })
}
fn parse_decimal_literal(spelling: &str) -> Result<Numeric, SemanticError> {
    let (coefficient, exponent) = spelling
        .split_once(['e', 'E'])
        .map_or((spelling, "0"), |(coefficient, exponent)| {
            (coefficient, exponent)
        });
    let exponent = exponent.replace('_', "");
    let exponent = exponent.parse::<i64>().map_err(|_| SemanticError {
        code: if exponent.starts_with('-') {
            "E_DECIMAL_SCALE_OVERFLOW"
        } else {
            "E_DECIMAL_MANTISSA_OVERFLOW"
        },
        message: "decimal exponent is outside the representable V1 domain".into(),
    })?;
    let (negative, coefficient) = coefficient
        .strip_prefix('-')
        .map_or((false, coefficient), |coefficient| (true, coefficient));
    let (whole, fractional) = coefficient
        .split_once('.')
        .map_or((coefficient, ""), |(whole, fractional)| (whole, fractional));
    let whole = whole.replace('_', "");
    let fractional = fractional.replace('_', "");
    let combined = format!("{whole}{fractional}");
    let significant = combined.trim_start_matches('0');
    if significant.is_empty() {
        return Ok(Numeric::zero());
    }
    let mut mantissa_spelling = significant.to_owned();
    let mut scale = i64::try_from(fractional.len())
        .map_err(|_| SemanticError {
            code: "E_DECIMAL_SCALE_OVERFLOW",
            message: "decimal literal scale exceeds the V1 maximum of 28".into(),
        })?
        .checked_sub(exponent)
        .ok_or_else(|| SemanticError {
            code: if exponent.is_negative() {
                "E_DECIMAL_SCALE_OVERFLOW"
            } else {
                "E_DECIMAL_MANTISSA_OVERFLOW"
            },
            message: "decimal exponent is outside the representable V1 domain".into(),
        })?;
    if scale < 0 {
        let zeros = usize::try_from(scale.unsigned_abs()).map_err(|_| SemanticError {
            code: "E_DECIMAL_MANTISSA_OVERFLOW",
            message: "decimal literal exceeds the signed 512-bit mantissa domain".into(),
        })?;
        if mantissa_spelling.len().saturating_add(zeros) > 154 {
            return Err(SemanticError {
                code: "E_DECIMAL_MANTISSA_OVERFLOW",
                message: "decimal literal exceeds the signed 512-bit mantissa domain".into(),
            });
        }
        mantissa_spelling.extend(core::iter::repeat_n('0', zeros));
        scale = 0;
    }
    while scale > 0 && mantissa_spelling.ends_with('0') {
        mantissa_spelling.pop();
        scale -= 1;
    }
    let scale = u32::try_from(scale).map_err(|_| SemanticError {
        code: "E_DECIMAL_SCALE_OVERFLOW",
        message: "decimal literal scale exceeds the V1 maximum of 28".into(),
    })?;
    if scale > 28 {
        return Err(SemanticError {
            code: "E_DECIMAL_SCALE_OVERFLOW",
            message: format!("decimal literal has canonical scale {scale}; the V1 maximum is 28"),
        });
    }
    if negative {
        mantissa_spelling.insert(0, '-');
    }
    let mantissa = mantissa_spelling
        .parse::<BigInt>()
        .map_err(|_| SemanticError {
            code: "E_DECIMAL_MANTISSA_OVERFLOW",
            message: "decimal literal exceeds the signed 512-bit mantissa domain".into(),
        })?;
    Numeric::try_new(mantissa, scale)
        .map_err(|error| match error {
            NumericError::MantissaTooLarge => SemanticError {
                code: "E_DECIMAL_MANTISSA_OVERFLOW",
                message: "decimal literal exceeds the signed 512-bit mantissa domain".into(),
            },
            NumericError::ScaleTooLarge => SemanticError {
                code: "E_DECIMAL_SCALE_OVERFLOW",
                message: "decimal literal scale exceeds the V1 maximum of 28".into(),
            },
            NumericError::Malformed => SemanticError {
                code: "E_DECIMAL_MALFORMED",
                message: "invalid decimal literal".into(),
            },
        })?
        .canonicalize_decimal()
        .map_err(|error| SemanticError {
            code: "E_DECIMAL_MALFORMED",
            message: format!("invalid decimal literal: {error}"),
        })
}
/// Normalize builtin argument labels under the registry's published rule.
///
/// A label equal to the declared parameter name is always accepted. An
/// unlabeled argument in a slot whose label is optional
/// ([`kotodama_surface::builtins::BuiltinCallPolicy::label_required`]) is positional. In a slot that
/// requires a label, a bare identifier spelled exactly like the label is label
/// punning: it is the labelled argument `label: label` and produces the same
/// typed call. Returns the per-argument labels for
/// [`reorder_call_arguments`] and whether the source labelled any argument.
fn builtin_argument_labels(
    builtin: Builtin,
    call_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    parameter_names: &[String],
) -> Result<(Vec<Option<String>>, bool), SemanticError> {
    let receiver_count = usize::from(implicit_receiver);
    let user_args = args.get(receiver_count..).unwrap_or_default();
    let policy = builtin.call_policy();
    let mut labels = Vec::with_capacity(user_args.len());
    let mut labelled = false;
    let mut named_seen = false;
    for (index, argument) in user_args.iter().enumerate() {
        if let Some(label) = argument_names.and_then(|names| names.get(index).cloned().flatten()) {
            named_seen = true;
            labelled = true;
            labels.push(Some(label));
            continue;
        }
        let Some(parameter) = parameter_names.get(index).filter(|_| !named_seen) else {
            // Positional-after-named and surplus arguments keep their source
            // shape so the shared reorder reports the precise error.
            labels.push(None);
            continue;
        };
        if !policy.label_required(index + receiver_count) {
            labels.push(Some(parameter.clone()));
        } else if matches!(argument.kind(), Expr::Ident(name) if name == parameter) {
            labelled = true;
            labels.push(Some(parameter.clone()));
        } else {
            return Err(SemanticError {
                code: "E_NAMED_ARGUMENTS_REQUIRED",
                message: misplaced_label_message(call_name, parameter, argument, parameter_names),
            });
        }
    }
    Ok((labels, labelled))
}
/// Message for an unlabelled argument in a builtin slot whose label is required.
///
/// A bare identifier spelled like a *different* parameter is a pun placed in
/// the wrong slot; saying so keeps the message from asking for a variable the
/// call already passes.
fn misplaced_label_message(
    call_name: &str,
    parameter: &str,
    argument: &Expr,
    parameter_names: &[String],
) -> String {
    match argument.kind() {
        Expr::Ident(name) if parameter_names.contains(name) => format!(
            "parameter `{parameter}` of `{call_name}` requires its label; `{name}` is spelled like parameter `{name}`, and a bare identifier fills only the slot of the same name, so label the arguments or pass them in declaration order"
        ),
        _ => format!(
            "parameter `{parameter}` of `{call_name}` requires its label; write `{parameter}: ...` or pass a variable named `{parameter}`"
        ),
    }
}
/// The `K2004` rejection of a source call to the runtime function `name` (a
/// kotoage, view or lifecycle hook), with help attached at the call.
fn runtime_function_call_error(
    context: &SemanticContext,
    call: &Expr,
    name: &str,
) -> SemanticError {
    context.capture_help(
        context.expression_source(call),
        type_help::runtime_entrypoint_call_help(name),
    );
    SemanticError {
        code: "K2004",
        message: format!(
            "seiyaku runtime function `{name}` cannot be called directly; move shared logic into a private `fn` or use the authorized inter-seiyaku call boundary"
        ),
    }
}
/// Reorder builtin call arguments after applying [`builtin_argument_labels`].
fn reorder_builtin_call_arguments(
    builtin: Builtin,
    call_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    parameter_names: &[String],
    required: &[bool],
) -> Result<CallArgumentPlan, SemanticError> {
    let (labels, labelled) = builtin_argument_labels(
        builtin,
        call_name,
        args,
        argument_names,
        implicit_receiver,
        parameter_names,
    )?;
    let mut plan = reorder_call_arguments(
        call_name,
        args,
        Some(&labels),
        implicit_receiver,
        parameter_names,
        required,
        0,
    )?;
    plan.is_named = labelled;
    Ok(plan)
}
/// Reorder a compiler-owned receiver method or numeric conversion call whose
/// every parameter accepts either a positional value or its declared label.
///
/// This is the label rule's "receiver methods and pure helpers" case for the
/// List, StateMap paging, rounding and conversion intrinsics that are not
/// registry builtins.
fn reorder_flexible_call_arguments(
    call_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    parameter_names: &[String],
    required: &[bool],
) -> Result<CallArgumentPlan, SemanticError> {
    let receiver_count = usize::from(implicit_receiver);
    let user_args = args.get(receiver_count..).unwrap_or_default();
    let mut labelled = false;
    let mut named_seen = false;
    let labels = (0..user_args.len())
        .map(|index| {
            let label = argument_names.and_then(|names| names.get(index).cloned().flatten());
            if label.is_some() {
                named_seen = true;
                labelled = true;
                return label;
            }
            if named_seen {
                return None;
            }
            parameter_names.get(index).cloned()
        })
        .collect::<Vec<_>>();
    let mut plan = reorder_call_arguments(
        call_name,
        args,
        Some(&labels),
        implicit_receiver,
        parameter_names,
        required,
        0,
    )
    .map_err(|mut error| {
        // These intrinsics have no registry signature for help text to cite,
        // so an unknown label names the declared ones directly.
        if error.code == "E_UNKNOWN_NAMED_ARGUMENT" {
            let declared = parameter_names
                .iter()
                .map(|parameter| format!("`{parameter}`"))
                .collect::<Vec<_>>()
                .join(", ");
            error.message = format!("{}; its parameters are {declared}", error.message);
        }
        error
    })?;
    plan.is_named = labelled;
    Ok(plan)
}
/// Render the corrected, fully labelled builtin call for a machine fix-it.
///
/// Only arguments whose source spelling can be reproduced exactly from the
/// AST (identifiers, literals, member paths and calls over those) are
/// rendered; any other argument suppresses the fix and leaves the help text.
/// A bare identifier spelled like a parameter label keeps that label, so the
/// fix for a swapped `ledger::nft::mint(owner, nft)` is
/// `ledger::nft::mint(owner: owner, nft: nft)` and never encodes the swap.
fn labelled_builtin_call_fix(
    call_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    parameter_names: &[String],
) -> Option<String> {
    let explicit =
        |index: usize| argument_names.and_then(|names| names.get(index).cloned().flatten());
    let punned = |argument: &Expr| match argument.kind() {
        Expr::Ident(name) if parameter_names.contains(name) => Some(name.clone()),
        _ => None,
    };
    // Labels already claimed by explicit labels or by punned identifiers.
    let claimed = args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| explicit(index).or_else(|| punned(argument)))
        .collect::<Vec<_>>();
    let mut free = parameter_names
        .iter()
        .filter(|name| !claimed.contains(name))
        .cloned();
    let mut rendered = Vec::with_capacity(args.len());
    let mut named_seen = false;
    for (index, argument) in args.iter().enumerate() {
        let label = match explicit(index) {
            Some(label) => {
                named_seen = true;
                label
            }
            None if !named_seen => match punned(argument) {
                Some(label) => label,
                None => free.next()?,
            },
            None => return None,
        };
        rendered.push(format!("{label}: {}", render_simple_expr(argument)?));
    }
    Some(format!("{call_name}({})", rendered.join(", ")))
}
/// Reproduce the source spelling of a simple expression, if it has one.
fn render_simple_expr(expression: &Expr) -> Option<String> {
    Some(match expression.kind() {
        Expr::Ident(name) => name.clone(),
        Expr::Bool(value) => value.to_string(),
        Expr::IntLiteral(value) => value.to_string(),
        Expr::DecimalLiteral(spelling) => spelling.clone(),
        Expr::String(value) => {
            let mut quoted = String::from("\"");
            for character in value.chars() {
                match character {
                    '"' => quoted.push_str("\\\""),
                    '\\' => quoted.push_str("\\\\"),
                    '\n' => quoted.push_str("\\n"),
                    '\t' => quoted.push_str("\\t"),
                    '\r' => quoted.push_str("\\r"),
                    character if character.is_control() => return None,
                    character => quoted.push(character),
                }
            }
            quoted.push('"');
            quoted
        }
        Expr::Member { object, field } => format!("{}.{field}", render_simple_expr(object)?),
        Expr::Call {
            name,
            args,
            argument_names,
            implicit_receiver: false,
        } => {
            let arguments = args
                .iter()
                .enumerate()
                .map(|(index, argument)| {
                    let value = render_simple_expr(argument)?;
                    Some(
                        match argument_names
                            .as_ref()
                            .and_then(|names| names.get(index).cloned().flatten())
                        {
                            Some(label) => format!("{label}: {value}"),
                            None => value,
                        },
                    )
                })
                .collect::<Option<Vec<_>>>()?;
            format!("{name}({})", arguments.join(", "))
        }
        _ => return None,
    })
}
#[derive(Debug)]
struct CallArgumentPlan {
    /// Arguments in declaration/ABI order.
    ordered: Vec<Expr>,
    /// Indices into `ordered` in source evaluation order.
    evaluation_order: Vec<usize>,
    /// Whether the source call supplied any named arguments.
    is_named: bool,
}
/// Point a builtin argument-type failure at the first argument that does not fit.
fn capture_builtin_argument_help(
    context: &SemanticContext,
    builtin: Builtin,
    error: &SemanticError,
    args: &[Expr],
    argument_types: &[Type],
) {
    if error.code == "E_INVALID_ID_LITERAL"
        && let (Builtin::PointerConstructor(constructor), Some(argument)) = (builtin, args.first())
        && let Expr::String(raw) = argument.kind()
        && let Err(invalid) = id_literals::validate(
            constructor,
            raw,
            iroha_data_model::account::address::chain_discriminant(),
        )
        && let Some(primary) = context.expression_source(argument)
    {
        context.capture_structured(
            crate::semantic_diagnostics::SemanticDiagnostic::at(
                primary,
                invalid.canonical.map(|canonical| {
                    crate::semantic_diagnostics::SemanticFix::Replace {
                        replacement: format!("\"{canonical}\""),
                    }
                }),
            )
            .with_help(invalid.help),
        );
        return;
    }
    if error.code != "K2003" {
        return;
    }
    if builtin == Builtin::Require
        && let (Some(argument), Some(Type::String)) = (args.get(1), argument_types.get(1))
    {
        context.capture_help(
            context.expression_source(argument),
            "`require` rejects with a typed error value, not a message string. Declare the reason once \
             in the seiyaku, for example `error enum VaultError { AmountMustBePositive = 1 }`, and \
             write `require(amount > 0, VaultError::AmountMustBePositive);`."
                .to_owned(),
        );
        return;
    }
    let signature = builtin.signature();
    // Only simple descriptors are interpreted here; anything else keeps the
    // statement-level span rather than guessing which argument failed.
    let accepts = |descriptor: &str, ty: &Type| -> Option<bool> {
        let ty = resolve_struct_type(ty);
        Some(match descriptor.strip_suffix('?').unwrap_or(descriptor) {
            "AccountId" => ty == Type::AccountId,
            "AssetDefinitionId" => ty == Type::AssetDefinitionId,
            "AssetId" => ty == Type::AssetId,
            "DataSpaceId" => ty == Type::DataSpaceId,
            "DomainId" => ty == Type::DomainId,
            "Json" => ty == Type::Json,
            "Name" => ty == Type::Name,
            "NftId" => ty == Type::NftId,
            "bool" => ty == Type::Bool,
            "bytes" => is_blob_like(&ty),
            // Exact numeric literals adopt a decimal or quantity context.
            "decimal" => matches!(ty, Type::Decimal | Type::Int),
            "int" => is_int_like(&ty),
            "quantity" => matches!(ty, Type::Quantity | Type::Decimal | Type::Int),
            "string" => ty == Type::String,
            _ => return None,
        })
    };
    let mismatch = argument_types
        .iter()
        .zip(signature.parameters.iter().copied())
        .enumerate()
        .find(|(_, (ty, descriptor))| accepts(descriptor, ty) == Some(false));
    if let Some((index, (ty, descriptor))) = mismatch
        && let Some(argument) = args.get(index)
    {
        let label = signature.parameter_names.get(index).map_or_else(
            || format!("argument {}", index + 1),
            |name| format!("`{name}:`"),
        );
        context.capture_help(
            context.expression_source(argument),
            format!(
                "{label} of `{}` expects `{}`, but this argument is {}.",
                builtin.source_name(),
                descriptor.trim_end_matches('?'),
                type_help::quoted(ty)
            ),
        );
    }
}
/// Attach declared-parameter help to an unknown-label failure.
fn capture_named_argument_help(
    context: &SemanticContext,
    call: &Expr,
    error: &SemanticError,
    call_name: &str,
    argument_names: Option<&[Option<String>]>,
    argument_count: usize,
    parameter_names: &[String],
) {
    if error.code == "K2003" && argument_count > parameter_names.len() {
        let declared = parameter_names
            .iter()
            .map(|parameter| format!("`{parameter}`"))
            .collect::<Vec<_>>();
        context.capture_help(
            context.expression_source(call),
            if declared.is_empty() {
                format!("`{call_name}` takes no arguments; remove them.")
            } else {
                format!(
                    "`{call_name}` declares {} parameter(s): {}. Remove the extra arguments.",
                    declared.len(),
                    declared.join(", ")
                )
            },
        );
        return;
    }
    if error.code != "E_UNKNOWN_NAMED_ARGUMENT" {
        return;
    }
    let unknown = argument_names
        .map(|names| type_help::unknown_labels(names, parameter_names))
        .unwrap_or_default();
    context.capture_help(
        context.expression_source(call),
        type_help::unknown_labels_help(call_name, &unknown, parameter_names),
    );
}
fn reorder_call_arguments(
    call_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    parameter_names: &[String],
    required: &[bool],
    positional_prefix: usize,
) -> Result<CallArgumentPlan, SemanticError> {
    let receiver_count = usize::from(implicit_receiver);
    if args.len() < receiver_count || positional_prefix > parameter_names.len() {
        return Err(SemanticError {
            code: "E_MALFORMED_CALL",
            message: format!("call `{call_name}` has inconsistent receiver or parameter metadata"),
        });
    }
    let user_args = &args[receiver_count..];
    if user_args.len() > parameter_names.len() {
        return Err(SemanticError {
            code: "K2003",
            message: format!(
                "call `{call_name}` expects at most {} arguments, got {}",
                parameter_names.len(),
                user_args.len()
            ),
        });
    }
    if argument_names.is_some_and(|names| names.len() != user_args.len()) {
        return Err(SemanticError {
            code: "E_MALFORMED_CALL",
            message: format!("call `{call_name}` has inconsistent source argument metadata"),
        });
    }
    let mut source_slots = vec![None; parameter_names.len()];
    let mut named_seen = false;
    let mut positional_count = 0;
    for (source_index, _) in user_args.iter().enumerate() {
        let name = argument_names.and_then(|names| names[source_index].as_deref());
        let parameter_index = if let Some(name) = name {
            named_seen = true;
            let index = parameter_names
                .iter()
                .position(|parameter| parameter == name)
                .ok_or_else(|| SemanticError {
                    code: "E_UNKNOWN_NAMED_ARGUMENT",
                    message: type_help::unknown_labels_message(
                        call_name,
                        &argument_names
                            .map(|names| type_help::unknown_labels(names, parameter_names))
                            .unwrap_or_default(),
                    ),
                })?;
            if index < positional_prefix {
                return Err(SemanticError {
                    code: "E_POSITIONAL_ARGUMENT_REQUIRED",
                    message: format!(
                        "parameter `{name}` of `{call_name}` is declared positional; omit its label"
                    ),
                });
            }
            index
        } else {
            if named_seen {
                return Err(SemanticError {
                    code: "E_POSITIONAL_ARGUMENT_ORDER",
                    message: "positional arguments must precede named arguments".into(),
                });
            }
            let index = positional_count;
            positional_count += 1;
            if index >= positional_prefix {
                return Err(SemanticError {
                    code: "E_NAMED_ARGUMENTS_REQUIRED",
                    message: parameter_names.get(index).map_or_else(
                        || format!("call `{call_name}` has too many positional arguments"),
                        |parameter| format!("parameter `{parameter}` of `{call_name}` requires its declared name"),
                    ),
                });
            }
            index
        };
        if source_slots[parameter_index]
            .replace(source_index)
            .is_some()
        {
            return Err(SemanticError {
                code: "E_DUPLICATE_NAMED_ARGUMENT",
                message: format!(
                    "argument `{}` is supplied more than once",
                    parameter_names[parameter_index]
                ),
            });
        }
    }
    let mut ordered = Vec::with_capacity(args.len());
    let mut evaluation_order = vec![0; args.len()];
    if implicit_receiver {
        ordered.push(args[0].clone());
    }
    let mut first_omitted_optional = None;
    for (index, source_index) in source_slots.iter().enumerate() {
        let parameter_name = &parameter_names[index];
        if let Some(source_index) = source_index {
            if let Some(omitted) = first_omitted_optional
                && !required.get(index).copied().unwrap_or(true)
            {
                return Err(SemanticError {
                    code: "E_NAMED_ARGUMENT_HOLE",
                    message: format!(
                        "optional named argument `{parameter_name}` cannot be supplied while earlier optional parameter `{omitted}` is omitted"
                    ),
                });
            }
            evaluation_order[source_index + receiver_count] = ordered.len();
            ordered.push(user_args[*source_index].clone());
        } else if required.get(index).copied().unwrap_or(true) {
            return Err(SemanticError {
                code: "E_MISSING_NAMED_ARGUMENT",
                message: format!(
                    "call `{call_name}` is missing required argument `{parameter_name}`"
                ),
            });
        } else if first_omitted_optional.is_none() {
            first_omitted_optional = Some(parameter_name);
        }
    }
    Ok(CallArgumentPlan {
        ordered,
        evaluation_order,
        is_named: named_seen,
    })
}
/// Append the compiler-owned [`crate::testing::TestCallSite`] record of a `test::` helper call as
/// its trailing argument, so test-mode lowering can report a failing seiyaku call or actor lookup
/// at the call's own source location.
///
/// The record is a literal with no runtime evaluation; a named call keeps its source evaluation
/// order and gains the record as its last slot.
fn append_test_call_site(
    context: &SemanticContext,
    call: &Expr,
    typed: TypedExpr,
) -> Result<TypedExpr, SemanticError> {
    let range = context.expression_source(call);
    let site = crate::testing::TestCallSite {
        source_id: range.map_or(0, |range| range.source.0),
        byte_start: range.map_or(0, |range| range.range.start),
        byte_end: range.map_or(0, |range| range.range.end),
    };
    let encoded =
        ivm_abi::codec::encode_canonical_norito(&site).map_err(|error| SemanticError {
            code: "K2003",
            message: format!("cannot encode the test call site: {error}"),
        })?;
    let site = TypedExpr {
        expr: ExprKind::Bytes(encoded),
        ty: Type::Bytes,
    };
    let TypedExpr { expr, ty } = typed;
    let expr = match expr {
        ExprKind::Call {
            target: name,
            mut args,
        } => {
            args.push(site);
            ExprKind::Call { target: name, args }
        }
        ExprKind::NamedCall {
            target: name,
            mut args,
            mut evaluation_order,
        } => {
            evaluation_order.push(args.len());
            args.push(site);
            ExprKind::NamedCall {
                target: name,
                args,
                evaluation_order,
            }
        }
        other => other,
    };
    Ok(TypedExpr { expr, ty })
}
fn retain_named_call_evaluation_order(typed: TypedExpr, plan: &CallArgumentPlan) -> TypedExpr {
    if !plan.is_named {
        return typed;
    }
    let TypedExpr { expr, ty } = typed;
    let expr = match expr {
        ExprKind::Call { target: name, args } if args.len() == plan.ordered.len() => {
            ExprKind::NamedCall {
                target: name,
                args,
                evaluation_order: plan.evaluation_order.clone(),
            }
        }
        // Some compiler-owned test intrinsics consume literal selector
        // arguments into the canonical callee name. Those total literals no
        // longer have runtime slots, so the source permutation cannot be
        // transferred to the smaller internal call and is unnecessary.
        other => other,
    };
    TypedExpr { expr, ty }
}
pub(crate) fn is_numeric_type(ty: &Type) -> bool {
    numeric_kind(ty).is_some()
}
pub(crate) fn is_wide_numeric_type(ty: &Type) -> bool {
    matches!(
        resolve_struct_type(ty),
        Type::Int | Type::Decimal | Type::Quantity
    )
}
fn is_int_like(ty: &Type) -> bool {
    matches!(resolve_struct_type(ty), Type::Int)
}
fn numeric_result_type(lhs: &Type, rhs: &Type) -> Option<Type> {
    let lhs_resolved = resolve_struct_type(lhs);
    let rhs_resolved = resolve_struct_type(rhs);
    if lhs_resolved == rhs_resolved {
        return numeric_kind(&lhs_resolved).map(numeric_kind_to_type);
    }
    None
}
fn arithmetic_result_type(op: BinaryOp, lhs: &Type, rhs: &Type) -> Option<Type> {
    let lhs = resolve_struct_type(lhs);
    let rhs = resolve_struct_type(rhs);
    match (op, &lhs, &rhs) {
        (_, Type::Int, Type::Int) => Some(Type::Int),
        (BinaryOp::Mod, Type::Decimal, Type::Decimal) => None,
        (_, Type::Decimal, Type::Decimal) => Some(Type::Decimal),
        (BinaryOp::Add | BinaryOp::Sub, Type::Quantity, Type::Quantity) => Some(Type::Quantity),
        (BinaryOp::Mul, Type::Quantity, Type::Decimal)
        | (BinaryOp::Div, Type::Quantity, Type::Decimal) => Some(Type::Quantity),
        (BinaryOp::Div, Type::Quantity, Type::Quantity) => Some(Type::Decimal),
        _ => None,
    }
}
fn literal_int(expr: &TypedExpr) -> Option<BigInt> {
    match expr.kind() {
        ExprKind::IntLiteral(value) => Some(value.clone()),
        ExprKind::NumericCast { expr } => literal_int(expr),
        ExprKind::Unary {
            op: UnaryOp::Neg,
            expr,
        } => literal_int(expr).and_then(|value| value.checked_neg().ok()),
        _ => None,
    }
}
fn reject_implicit_int_decimal_mix(lhs: &Type, rhs: &Type) -> Result<(), SemanticError> {
    let lhs = resolve_struct_type(lhs);
    let rhs = resolve_struct_type(rhs);
    if !matches!(
        (&lhs, &rhs),
        (Type::Int, Type::Decimal) | (Type::Decimal, Type::Int)
    ) {
        return Ok(());
    }
    Err(SemanticError {
        code: "E_IMPLICIT_NUMERIC_CONVERSION",
        message: "`int` and `decimal` operands cannot be mixed implicitly; convert the `int` with `decimal::from_int(value)` before arithmetic or comparison"
            .into(),
    })
}
fn explicit_numeric_conversion(
    name: &str,
    args: Vec<TypedExpr>,
) -> Option<Result<TypedExpr, SemanticError>> {
    if name == "decimal::to_int_trunc" {
        return Some((|| {
            if args.len() != 1 || resolve_struct_type(&args[0].ty) != Type::Decimal {
                return Err(SemanticError {
                    code: "K2003",
                    message: "decimal::to_int_trunc expects exactly one decimal argument".into(),
                });
            }
            if let Some(crate::checked_arithmetic::ConstantNumeric::Decimal(value)) =
                crate::checked_arithmetic::evaluate(&args[0]).map_err(|error| SemanticError {
                    code: error.code(),
                    message: error.to_string(),
                })?
            {
                let value = value.decimal_to_int_trunc().map_err(|error| {
                    let error = crate::checked_arithmetic::ConstantNumericError::Numeric(error);
                    SemanticError {
                        code: error.code(),
                        message: error.to_string(),
                    }
                })?;
                return Ok(TypedExpr {
                    expr: ExprKind::IntLiteral(value),
                    ty: Type::Int,
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Intrinsic(CompilerIntrinsic::DecimalToIntTrunc),
                    args,
                },
                ty: Type::Int,
            })
        })());
    }
    let (source, destination, recoverable) = match name {
        "decimal::from_int" => (Type::Int, Type::Decimal, false),
        "decimal::to_int_exact" => (Type::Decimal, Type::Int, false),
        "quantity::try_from_int" => (Type::Int, Type::Quantity, true),
        "quantity::try_from_decimal" => (Type::Decimal, Type::Quantity, true),
        "decimal::from_quantity" => (Type::Quantity, Type::Decimal, false),
        _ => return None,
    };
    Some((|| {
        if args.len() != 1 || resolve_struct_type(&args[0].ty) != source {
            return Err(SemanticError {
                code: "K2003",
                message: format!("{name} expects exactly one {} argument", type_name(&source)),
            });
        }
        let argument = Box::new(args.into_iter().next().expect("one argument checked"));
        if recoverable {
            return Ok(TypedExpr {
                expr: ExprKind::NumericTryCast { expr: argument },
                ty: Type::Result(
                    Box::new(destination),
                    Box::new(Type::ErrorEnum(Arc::new(
                        ivm_abi::error_types::numeric_error_type(),
                    ))),
                ),
            });
        }
        Ok(TypedExpr {
            expr: ExprKind::NumericCast { expr: argument },
            ty: destination,
        })
    })())
}
fn numeric_literal_is_negative(expr: &TypedExpr) -> bool {
    match expr.kind() {
        ExprKind::IntLiteral(value) => value.is_negative(),
        ExprKind::DecimalLiteral { value, .. } => value.mantissa().is_negative(),
        ExprKind::Unary {
            op: UnaryOp::Neg,
            expr,
        } => !numeric_literal_is_zero(expr),
        _ => false,
    }
}
fn numeric_literal_is_zero(expr: &TypedExpr) -> bool {
    match expr.kind() {
        ExprKind::IntLiteral(value) => value.is_zero(),
        ExprKind::DecimalLiteral { value, .. } => value.is_zero(),
        _ => false,
    }
}
fn is_supported_durable_value_type(ty: &Type) -> bool {
    match resolve_struct_type(ty) {
        ty if is_numeric_type(&ty) => true,
        Type::Unit
        | Type::Enum(_)
        | Type::ErrorEnum(_)
        | Type::Bool
        | Type::String
        | Type::Json
        | Type::Bytes => true,
        other if is_pointer_type(&other) => true,
        Type::Struct { fields, .. } => fields
            .iter()
            .all(|(_, field_ty)| is_supported_durable_value_type(field_ty)),
        Type::Tuple(items) => items.iter().all(is_supported_durable_value_type),
        Type::Option(inner) => is_supported_durable_value_type(&inner),
        Type::Result(ok, err) => {
            is_supported_durable_value_type(&ok) && is_supported_durable_value_type(&err)
        }
        Type::List(element, _) => is_supported_durable_value_type(&element),
        _ => false,
    }
}
fn coerce_exact_numeric_literal_to(
    expr: &mut TypedExpr,
    expected: &Type,
) -> Result<(), SemanticError> {
    if resolve_struct_type(&expr.ty) != resolve_struct_type(expected)
        && exact_numeric_literal_expression(expr)
    {
        ensure_assignable_and_coerce(expected, expr)?;
    }
    Ok(())
}
/// Apply the expected numeric domain only to exact literal operands.
///
/// Runtime values retain their nominal type: this is literal inference, not
/// an implicit conversion between `int`, `decimal`, and `quantity` values.
fn coerce_contextual_numeric_literals(
    op: BinaryOp,
    expected: Option<&Type>,
    left: &mut TypedExpr,
    right: &mut TypedExpr,
) -> Result<(), SemanticError> {
    use BinaryOp::*;
    let comparison = matches!(op, Eq | Ne | Lt | Le | Gt | Ge);
    let left_type = resolve_struct_type(&left.ty);
    let right_type = resolve_struct_type(&right.ty);
    if left_type == Type::Quantity {
        match op {
            Add | Sub | Mod if exact_numeric_literal_expression(right) => {
                coerce_exact_numeric_literal_to(right, &Type::Quantity)?;
            }
            Mul if exact_numeric_literal_expression(right) => {
                coerce_exact_numeric_literal_to(right, &Type::Decimal)?;
            }
            Div if exact_numeric_literal_expression(right) => {
                let divisor_type = if expected
                    .is_some_and(|expected| resolve_struct_type(expected) == Type::Decimal)
                {
                    Type::Quantity
                } else {
                    Type::Decimal
                };
                coerce_exact_numeric_literal_to(right, &divisor_type)?;
            }
            _ if comparison && exact_numeric_literal_expression(right) => {
                coerce_exact_numeric_literal_to(right, &Type::Quantity)?;
            }
            _ => {}
        }
        return Ok(());
    }
    if right_type == Type::Quantity {
        if matches!(op, Add | Sub | Mod) || comparison {
            coerce_exact_numeric_literal_to(left, &Type::Quantity)?;
        }
        return Ok(());
    }
    // A sibling decimal operand provides a compile-time type context for an
    // exact literal. This retags and folds only literal syntax; an existing
    // runtime `int` is never wrapped in a hidden `NumericCast`.
    if left_type == Type::Decimal && exact_numeric_literal_expression(right) {
        coerce_exact_numeric_literal_to(right, &Type::Decimal)?;
    } else if right_type == Type::Decimal && exact_numeric_literal_expression(left) {
        coerce_exact_numeric_literal_to(left, &Type::Decimal)?;
    }
    match expected.map(resolve_struct_type) {
        Some(Type::Decimal) if matches!(op, Add | Sub | Mul | Div | Mod) => {
            coerce_exact_numeric_literal_to(left, &Type::Decimal)?;
            coerce_exact_numeric_literal_to(right, &Type::Decimal)?;
        }
        Some(Type::Quantity) => match op {
            Add | Sub | Mod => {
                coerce_exact_numeric_literal_to(left, &Type::Quantity)?;
                coerce_exact_numeric_literal_to(right, &Type::Quantity)?;
            }
            Mul | Div => {
                coerce_exact_numeric_literal_to(left, &Type::Quantity)?;
                coerce_exact_numeric_literal_to(right, &Type::Decimal)?;
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}
fn list_element_contains_resource_handle(ty: &Type) -> bool {
    match resolve_struct_type(ty) {
        Type::Secret(_)
        | Type::StateMap(_, _)
        | Type::AxtAnchoredSpendV1
        | Type::ContractRef(_) => true,
        Type::List(element, _) | Type::Option(element) => {
            list_element_contains_resource_handle(&element)
        }
        Type::Result(ok, err) => {
            list_element_contains_resource_handle(&ok)
                || list_element_contains_resource_handle(&err)
        }
        Type::Tuple(items) => items.iter().any(list_element_contains_resource_handle),
        Type::Struct { fields, .. } => fields
            .iter()
            .any(|(_, field)| list_element_contains_resource_handle(field)),
        _ => false,
    }
}
/// Return the recursively flattened V1 function-ABI word count, capped at one more than `limit`.
///
/// Product fields are visited only until the caller's bounded ABI table is
/// exceeded. This is important for canonical named-struct DAGs: repeatedly
/// referring to the same shared branching type must not restore an expanded
/// tree walk after named-type resolution proved the graph itself was bounded.
pub(crate) fn runtime_value_word_count_bounded(ty: &Type, limit: usize) -> Option<usize> {
    fn count(ty: &Type, limit: usize) -> Option<usize> {
        let children: &[Type] = match ty {
            Type::Tuple(items) => items,
            Type::Struct { fields, .. } => {
                let mut total = 0_usize;
                for (_, field) in fields.iter() {
                    let remaining = limit.saturating_sub(total);
                    let words = count(field, remaining)?;
                    if words > remaining {
                        return Some(limit.saturating_add(1));
                    }
                    total = total.checked_add(words)?;
                }
                return Some(total.max(1));
            }
            Type::NamedStruct(_) => return None,
            // Every scalar and every compiler-owned Option, Result, or List
            // handle occupies exactly one function-ABI word. Empty products
            // similarly transport one initialized Unit slot.
            _ => return Some(1),
        };
        let mut total = 0_usize;
        for child in children {
            let remaining = limit.saturating_sub(total);
            let words = count(child, remaining)?;
            if words > remaining {
                return Some(limit.saturating_add(1));
            }
            total = total.checked_add(words)?;
        }
        Some(total.max(1))
    }
    count(ty, limit)
}
/// Encoding accepts public values but excludes execution-bound cursor capabilities.
fn is_encodable_public_value(ty: &Type) -> bool {
    match resolve_struct_type(ty) {
        Type::StateCursor(_) => false,
        Type::Struct { fields, .. } => fields
            .iter()
            .all(|(_, field)| is_encodable_public_value(field)),
        Type::Tuple(items) => items.iter().all(is_encodable_public_value),
        Type::Option(payload) | Type::List(payload, _) => is_encodable_public_value(&payload),
        Type::Result(ok, error) => {
            is_encodable_public_value(&ok) && is_encodable_public_value(&error)
        }
        other => is_supported_public_argument_type(&other),
    }
}
fn is_supported_public_argument_type(ty: &Type) -> bool {
    match resolve_struct_type(ty) {
        Type::Int
        | Type::Decimal
        | Type::Quantity
        | Type::Bool
        | Type::String
        | Type::Json
        | Type::Bytes
        | Type::AccountId
        | Type::AssetDefinitionId
        | Type::AssetId
        | Type::DomainId
        | Type::NftId
        | Type::Name
        | Type::DataSpaceId
        | Type::Unit
        | Type::StateCursor(_)
        | Type::Enum(_)
        | Type::ErrorEnum(_) => true,
        Type::Struct { fields, .. } => fields
            .iter()
            .all(|(_, field_ty)| is_supported_public_argument_type(field_ty)),
        Type::Tuple(items) => items.iter().all(is_supported_public_argument_type),
        Type::Option(inner) => is_supported_public_argument_type(&inner),
        Type::Result(ok, err) => {
            is_supported_public_argument_type(&ok) && is_supported_public_argument_type(&err)
        }
        Type::List(element, _) => is_supported_public_argument_type(&element),
        Type::Secret(_)
        | Type::StateMap(_, _)
        | Type::AxtDescriptor
        | Type::AxtAnchoredSpendV1
        | Type::ProofBlob
        | Type::SoracloudRequest
        | Type::SoracloudResponse
        | Type::NamedStruct(_)
        | Type::ContractRef(_) => false,
    }
}
pub(crate) fn is_supported_durable_key_type(ty: &Type) -> bool {
    crate::abi_schema::state_map_key_schema(&resolve_struct_type(ty)).is_some()
}
fn is_in_memory_map_word_type(ty: &Type) -> bool {
    match resolve_struct_type(ty) {
        ty if is_numeric_type(&ty) => true,
        Type::Unit
        | Type::Enum(_)
        | Type::ErrorEnum(_)
        | Type::Bool
        | Type::String
        | Type::Bytes
        | Type::Json => true,
        other if is_pointer_type(&other) => true,
        _ => false,
    }
}
fn ensure_in_memory_map_word_types(
    context: &SemanticContext,
    map_expr: &TypedExpr,
) -> Result<(), SemanticError> {
    if typed_map_expr_is_state(context, map_expr) {
        return Ok(());
    }
    if let Type::StateMap(k, v) = resolve_struct_type(&map_expr.ty) {
        if !is_in_memory_map_word_type(&k) {
            return Err(SemanticError {
                code: "K2003",
                message: format!(
                    "ephemeral map key type `{}` is not supported; use int, decimal, quantity, bool, string, bytes, Json, or typed Iroha IDs",
                    type_name(&k)
                ),
            });
        }
        if !is_in_memory_map_word_type(&v) {
            return Err(SemanticError {
                code: "K2003",
                message: format!(
                    "ephemeral map value type `{}` is not supported; use int, decimal, quantity, bool, string, bytes, Json, or typed Iroha IDs",
                    type_name(&v)
                ),
            });
        }
    }
    Ok(())
}
fn validate_state_type(ty: &Type) -> Result<(), SemanticError> {
    validate_state_type_inner(ty, true)
}
fn validate_state_type_inner(ty: &Type, allow_map: bool) -> Result<(), SemanticError> {
    if crate::secret::type_contains_secret(ty) {
        return Err(SemanticError {
            code: "E_SECRET_STATE_TYPE",
            message: "durable state cannot contain Secret<T>; private inputs are execution-local"
                .into(),
        });
    }
    match resolve_struct_type(ty) {
        Type::StateMap(k, v) => {
            if !allow_map {
                return Err(SemanticError {
                    code: "K2005",
                    message:
                        "nested StateMap is not supported in Kotodama V1; declare each StateMap as top-level state"
                            .into(),
                });
            }
            if !is_supported_durable_key_type(&k) {
                return Err(SemanticError {
                    code: "E_STATE_MAP_KEY_TYPE",
                    message: format!(
                        "StateMap key type `{}` is not supported for durable storage; use canonical scalar leaves or tuples of those leaves",
                        type_name(&k)
                    ),
                });
            }
            if !is_supported_durable_value_type(&v) {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "StateMap value type `{}` is not supported for durable storage; use a canonical V1 value type",
                        type_name(&v)
                    ),
                });
            }
            Ok(())
        }
        Type::Struct { fields, .. } => {
            for (_, field_ty) in fields.iter() {
                validate_state_type_inner(field_ty, false)?;
            }
            Ok(())
        }
        Type::Tuple(items) => {
            for item in items {
                validate_state_type_inner(&item, false)?;
            }
            Ok(())
        }
        other => {
            if is_supported_durable_value_type(&other) {
                Ok(())
            } else {
                Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "state type `{}` is not supported for durable storage; use int, decimal, quantity, bool, Json, bytes, typed Iroha IDs, or aggregate V1 types",
                        type_name(&other)
                    ),
                })
            }
        }
    }
}
pub(crate) fn is_blob_like(ty: &Type) -> bool {
    matches!(resolve_struct_type(ty), Type::Bytes)
}
fn pointer_constructor_type(constructor: PointerConstructor) -> Type {
    match constructor {
        PointerConstructor::AccountId => Type::AccountId,
        PointerConstructor::AssetDefinition => Type::AssetDefinitionId,
        PointerConstructor::AssetId => Type::AssetId,
        PointerConstructor::NftId => Type::NftId,
        PointerConstructor::Domain | PointerConstructor::DomainId => Type::DomainId,
        PointerConstructor::Name => Type::Name,
        PointerConstructor::Json => Type::Json,
        PointerConstructor::Blob | PointerConstructor::NoritoBytes => Type::Bytes,
        PointerConstructor::DataSpaceId => Type::DataSpaceId,
        PointerConstructor::AxtDescriptor => Type::AxtDescriptor,
        PointerConstructor::AxtAnchoredSpendV1 => Type::AxtAnchoredSpendV1,
        PointerConstructor::ProofBlob => Type::ProofBlob,
        PointerConstructor::SoracloudRequest => Type::SoracloudRequest,
        PointerConstructor::SoracloudResponse => Type::SoracloudResponse,
    }
}
fn is_eq_comparable_type(ty: &Type) -> bool {
    let mut pending = vec![ty];
    let mut visited_structs = HashSet::new();
    while let Some(ty) = pending.pop() {
        match ty {
            Type::Struct { fields, .. } => {
                // Resolved structs share their immutable field graph. Inspect each
                // allocation once instead of expanding repeated named products.
                if visited_structs.insert(fields.as_ptr()) {
                    pending.extend(fields.iter().map(|(_, field)| field));
                }
            }
            Type::Tuple(items) => pending.extend(items),
            Type::Option(inner) | Type::List(inner, _) => pending.push(inner),
            Type::Result(ok, err) => {
                pending.push(ok);
                pending.push(err);
            }
            Type::Int
            | Type::Decimal
            | Type::Quantity
            | Type::Unit
            | Type::Enum(_)
            | Type::ErrorEnum(_)
            | Type::Bool
            | Type::String
            | Type::Bytes
            | Type::Json => {}
            other if is_pointer_type(other) => {}
            _ => return false,
        }
    }
    true
}
pub fn is_pointer_type(ty: &Type) -> bool {
    crate::session::run_with_compiler_stack(move || is_pointer_type_inline(ty))
        .expect("compiler must allocate the bounded stack required to inspect a semantic type")
}
fn is_pointer_type_inline(ty: &Type) -> bool {
    matches!(
        resolve_struct_type(ty),
        Type::AccountId
            | Type::StateCursor(_)
            | Type::AssetDefinitionId
            | Type::AssetId
            | Type::DomainId
            | Type::NftId
            | Type::Name
            | Type::DataSpaceId
            | Type::AxtDescriptor
            | Type::AxtAnchoredSpendV1
            | Type::ProofBlob
            | Type::SoracloudRequest
            | Type::SoracloudResponse
    )
}
fn transfer_batch_element_type() -> Type {
    Type::Tuple(vec![
        Type::AccountId,
        Type::AccountId,
        Type::AssetDefinitionId,
        Type::Quantity,
    ])
}
fn ensure_transfer_batch_args(args: &[TypedExpr]) -> Result<(), SemanticError> {
    if let [argument] = args
        && let Type::List(element, capacity) = resolve_struct_type(&argument.ty)
        && (1..=64).contains(&capacity)
        && *element == transfer_batch_element_type()
    {
        return Ok(());
    }
    Err(SemanticError {
        code: "K2003",
        message: "transfer_batch expects named transfers: List<(AccountId, AccountId, AssetDefinitionId, quantity), N> with capacity N in 1..64".into(),
    })
}
/// Recursively bind nested struct fields into `name#i#j` variables for convenient lowering.
fn bind_struct_fields_rec(
    out: &mut Vec<TypedStatement>,
    vars: &mut HashMap<String, Type>,
    base_name: &str,
    base_expr: &TypedExpr,
    ty: &Type,
) {
    let resolved_ty = resolve_struct_type(ty);
    if let Type::Struct { fields, .. } = resolved_ty {
        for (i, (_fname, fty)) in fields.iter().enumerate() {
            // `base_expr` has already been captured by the synthetic binding
            // named `base_name`. Project from that binding so an effectful
            // aggregate expression is never evaluated once per field.
            let captured = TypedExpr {
                expr: ExprKind::Ident(base_name.to_owned()),
                ty: base_expr.ty.clone(),
            };
            let member = TypedExpr {
                expr: ExprKind::Member {
                    object: Box::new(captured),
                    field: i.to_string(),
                },
                ty: resolve_struct_type(fty),
            };
            let sname = format!("{base_name}#{i}");
            let field_ty = resolve_struct_type(fty);
            vars.insert(sname.clone(), field_ty.clone());
            out.push(TypedStatement::Let {
                name: sname.clone(),
                value: member.clone(),
            });
            bind_struct_fields_rec(out, vars, &sname, &member, &field_ty);
        }
    }
}
/// Recursively bind tuple elements into `name#i` variables so older lowering
/// helpers can access flattened names. Nested structs continue to use the
/// existing struct binding helper, and nested tuples recurse naturally.
fn bind_tuple_fields_rec(
    out: &mut Vec<TypedStatement>,
    vars: &mut HashMap<String, Type>,
    base_name: &str,
    base_expr: &TypedExpr,
    ty: &Type,
) {
    if let Type::Tuple(elements) = resolve_struct_type(ty) {
        for (idx, elem_ty) in elements.iter().enumerate() {
            let resolved_elem_ty = resolve_struct_type(elem_ty);
            // Tuple literals and calls are both evaluated by the parent
            // binding. Synthetic flattened names only project that captured
            // value; cloning a literal item here would also duplicate calls
            // nested inside the literal.
            let element_expr = TypedExpr {
                expr: ExprKind::Member {
                    object: Box::new(TypedExpr {
                        expr: ExprKind::Ident(base_name.to_owned()),
                        ty: base_expr.ty.clone(),
                    }),
                    field: idx.to_string(),
                },
                ty: resolved_elem_ty.clone(),
            };
            let child_name = format!("{base_name}#{idx}");
            vars.insert(child_name.clone(), resolved_elem_ty.clone());
            out.push(TypedStatement::Let {
                name: child_name.clone(),
                value: element_expr.clone(),
            });
            bind_tuple_fields_rec(out, vars, &child_name, &element_expr, &resolved_elem_ty);
            bind_struct_fields_rec(out, vars, &child_name, &element_expr, &resolved_elem_ty);
        }
    }
}
/// Rebuild each enclosing product around one changed field, retaining value
/// semantics instead of mutating storage shared by copies of the original.
fn rebuild_assigned_product(
    target: &TypedExpr,
    replacement: TypedExpr,
) -> Result<(String, TypedExpr), SemanticError> {
    match target.kind() {
        ExprKind::Ident(name) => Ok((name.clone(), replacement)),
        ExprKind::Member { object, field } => {
            let fields = match resolve_struct_type(&object.ty) {
                Type::Struct { name, fields } => {
                    let fields = fields
                        .iter()
                        .enumerate()
                        .map(|(index, (name, ty))| {
                            let value = if index.to_string() == *field {
                                replacement.clone()
                            } else {
                                TypedExpr {
                                    expr: ExprKind::Member {
                                        object: object.clone(),
                                        field: index.to_string(),
                                    },
                                    ty: ty.clone(),
                                }
                            };
                            (name.clone(), value)
                        })
                        .collect();
                    ExprKind::StructLiteral { name, fields }
                }
                Type::Tuple(types) => ExprKind::Tuple(
                    types
                        .into_iter()
                        .enumerate()
                        .map(|(index, ty)| {
                            if index.to_string() == *field {
                                replacement.clone()
                            } else {
                                TypedExpr {
                                    expr: ExprKind::Member {
                                        object: object.clone(),
                                        field: index.to_string(),
                                    },
                                    ty,
                                }
                            }
                        })
                        .collect(),
                ),
                _ => {
                    return Err(SemanticError {
                        code: "E_INVALID_ASSIGNMENT_TARGET",
                        message: "field assignment requires a struct or tuple binding".into(),
                    });
                }
            };
            rebuild_assigned_product(
                object,
                TypedExpr {
                    expr: fields,
                    ty: object.ty.clone(),
                },
            )
        }
        _ => Err(SemanticError {
            code: "E_INVALID_ASSIGNMENT_TARGET",
            message: "field assignment must be rooted in a mutable binding".into(),
        }),
    }
}
fn analyze_function(
    context: &SemanticContext,
    func: &Function,
) -> Result<TypedFunction, SemanticError> {
    context.discard_diagnostic();
    context.required_list_capacity.borrow_mut().take();
    if matches!(
        func.modifiers.kind,
        FunctionKind::Hajimari | FunctionKind::Kaizen
    ) && func.modifiers.authorization.is_some()
    {
        return Err(SemanticError {
            code: "E_LIFECYCLE_AUTHORIZATION",
            message: format!(
                "lifecycle function `{}` cannot declare caller authorization; lifecycle authorization is runtime-defined",
                func.name
            ),
        });
    }
    if func.modifiers.is_test {
        if !func.params.is_empty() {
            return Err(SemanticError {
                code: "E_TEST_FUNCTION_SIGNATURE",
                message: format!("test function `{}` must not declare parameters", func.name),
            });
        }
        if func.ret_ty.as_ref().is_some_and(
            |ty| !matches!(ty.kind(), TypeExpr::Tuple(elements) if elements.is_empty()),
        ) {
            return Err(SemanticError {
                code: "K2003",
                message: format!("test function `{}` must return Unit `()`", func.name),
            });
        }
        if func.modifiers.kind != FunctionKind::Private {
            return Err(SemanticError {
                code: "E_TEST_FUNCTION_SIGNATURE",
                message: format!(
                    "test function `{}` must be declared as a local `fn`",
                    func.name
                ),
            });
        }
        if func.modifiers.authorization.is_some() {
            return Err(SemanticError {
                code: "K2004",
                message: format!(
                    "test function `{}` cannot declare a permission modifier",
                    func.name
                ),
            });
        }
    }
    let mut vars = HashMap::new();
    let mut mutable_bindings = HashSet::new();
    let mut param_names = Vec::new();
    let mut param_types = Vec::new();
    // Seed variable environment with seiyaku-level state declarations so
    // functions can reference `state` names directly.
    {
        let states = context.states.borrow();
        for (name, ty) in states.iter() {
            vars.insert(name.clone(), ty.clone());
        }
    }
    let mut state_param_names = HashSet::new();
    for param in &func.params {
        ensure_new_local_binding(context, &param.name, &vars)?;
        let typed_param = parse_declared_param_type(context, param, &func.modifiers)?;
        vars.insert(param.name.clone(), typed_param.ty.clone());
        if typed_param.is_state {
            state_param_names.insert(param.name.clone());
        }
        param_names.push(param.name.clone());
        param_types.push(typed_param);
    }
    let expected_ret = Some(parse_declared_type(context, &func.ret_ty)?.unwrap_or(Type::Unit));
    if func.modifiers.kind != FunctionKind::Private
        && expected_ret
            .as_ref()
            .is_some_and(crate::secret::type_contains_secret)
    {
        context.capture_diagnostic(
            func.ret_ty.as_ref().and_then(|ty| context.type_source(ty)),
            None,
        );
        return Err(SemanticError {
            code: "E_SECRET_PUBLIC_RETURN",
            message: format!(
                "externally callable `{}` cannot return Secret<T>; return an approved commitment or proof result",
                func.name
            ),
        });
    }
    context.inferred_locals.borrow_mut().clear();
    context
        .current_return_source
        .replace(func.ret_ty.as_ref().and_then(|ty| context.type_source(ty)));
    let previous_modifiers = context
        .current_function_modifiers
        .borrow_mut()
        .replace(func.modifiers.clone());
    let previous_name = context
        .current_function_name
        .borrow_mut()
        .replace(func.name.clone());
    let previous_mutable_bindings =
        std::mem::take(&mut *context.current_mutable_bindings.borrow_mut());
    let previous_state_params = std::mem::replace(
        &mut *context.current_state_param_names.borrow_mut(),
        state_param_names.clone(),
    );
    let unit_return = Type::Unit;
    let expected_tail = expected_ret.as_ref().unwrap_or(&unit_return);
    context.recovered_failures.borrow_mut().clear();
    let recovery = context.statement_recovery.replace(true);
    let body_result = analyze_block(
        context,
        &func.body,
        &mut vars,
        &mut mutable_bindings,
        expected_ret.as_ref(),
        BlockTailContext {
            expected: Some(expected_tail),
            widen: true,
        },
        0,
    );
    context.statement_recovery.set(recovery);
    let mut recovered = std::mem::take(&mut *context.recovered_failures.borrow_mut());
    if !recovered.is_empty() {
        // The first recovered failure is the function's failure; later ones,
        // including a terminal error, are reported after it in source order.
        if let Err(error) = body_result {
            recovered.push((error, context.take_diagnostic()));
        }
        *context.current_function_modifiers.borrow_mut() = previous_modifiers;
        *context.current_function_name.borrow_mut() = previous_name;
        *context.current_mutable_bindings.borrow_mut() = previous_mutable_bindings;
        *context.current_state_param_names.borrow_mut() = previous_state_params;
        let (error, diagnostic) = recovered.remove(0);
        context.pending_diagnostic.replace(diagnostic);
        context.extra_failures.replace(recovered);
        return Err(error);
    }
    *context.current_function_modifiers.borrow_mut() = previous_modifiers;
    *context.current_function_name.borrow_mut() = previous_name;
    *context.current_mutable_bindings.borrow_mut() = previous_mutable_bindings;
    *context.current_state_param_names.borrow_mut() = previous_state_params;
    let body = body_result?;
    if let Err(failure) = crate::result_use::check_with_diagnostic(
        &param_types,
        &body,
        context.states.borrow().keys().cloned().collect(),
    ) {
        let (error, diagnostic) = *failure;
        if let Some(diagnostic) = diagnostic {
            context.pending_diagnostic.replace(Some(diagnostic));
        }
        return Err(error);
    }
    // Enforce declared return coverage and shape
    if let Some(t) = &expected_ret {
        if *t != Type::Unit && body.tail.is_none() && !typed_block_diverges(&body) {
            return Err(SemanticError {
                code: "E_MISSING_RETURN",
                message: "not all paths return a value".into(),
            });
        }
    } else {
        // No declared return type: disallow returning a value to avoid ambiguity
        if block_has_return_value(&func.body) {
            return Err(SemanticError {
                code: "K2003",
                message: "function returns a value but has no declared return type".into(),
            });
        }
    }
    let summary = FunctionSummary {
        direct_effects: block_effects(context, &body),
        calls: collect_called_functions(context, &body),
        sites: effect_sites::effect_sites(context, &body),
    };
    context
        .function_summaries
        .borrow_mut()
        .insert(func.name.clone(), summary);
    Ok(TypedFunction {
        name: func.name.clone(),
        params: param_names,
        param_types,
        body,
        ret_ty: expected_ret,
        modifiers: func.modifiers.clone(),
        location: func.location,
        source: None,
        name_source: None,
    })
}
fn reject_public_trigger_event(context: &SemanticContext, name: &str) -> Result<(), SemanticError> {
    let forbidden = context
        .current_function_modifiers
        .borrow()
        .as_ref()
        .is_some_and(|modifiers| match modifiers.kind {
            FunctionKind::View => true,
            FunctionKind::Kotoage | FunctionKind::Hajimari | FunctionKind::Kaizen => {
                !current_public_trigger_callback_allows_payload_helper(context)
            }
            FunctionKind::Private => false,
        });
    if forbidden {
        return Err(SemanticError {
            code: "K2003",
            message: format!(
                "`kotoage`/`言挙げ`, `view fn`, `hajimari`/`始まり`, and `kaizen`/`改善` declarations cannot use `{name}` here; declare typed parameters instead"
            ),
        });
    }
    Ok(())
}
fn current_public_trigger_callback_allows_payload_helper(context: &SemanticContext) -> bool {
    let current = context.current_function_name.borrow().clone();
    let Some(current) = current else {
        return false;
    };
    context
        .trigger_callback_functions
        .borrow()
        .contains(&current)
}
/// Whether the current function may use test-function-only builtins: a `#[test]` function, or
/// a private helper of a standalone `koto_test` module (which never reaches a deployable artifact).
fn current_function_is_test(context: &SemanticContext) -> bool {
    context
        .current_function_modifiers
        .borrow()
        .as_ref()
        .is_some_and(|modifiers| {
            modifiers.is_test
                || (context.standalone_test_module.get() && modifiers.kind == FunctionKind::Private)
        })
}
fn function_is_runtime_entrypoint(modifiers: &FunctionModifiers) -> bool {
    modifiers.kind != FunctionKind::Private
}
fn invoke_entrypoint_literal(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Source { expression, .. } | Expr::Resolved { expression, .. } => {
            invoke_entrypoint_literal(expression)
        }
        Expr::String(raw) => Some(raw.clone()),
        Expr::Call { name, args, .. }
            if normalize_namespaced(name) == "name" && args.len() == 1 =>
        {
            match args[0].kind() {
                Expr::String(raw) => Some(raw.clone()),
                Expr::Source { .. } | Expr::Resolved { .. } => {
                    unreachable!("kind() strips provenance wrappers")
                }
                _ => None,
            }
        }
        _ => None,
    }
}
fn typed_string_literal(value: String) -> TypedExpr {
    TypedExpr {
        expr: ExprKind::String(value),
        ty: Type::String,
    }
}
/// Analyze a closed source record against the exact public target's parameter types.
fn analyze_test_arguments(
    context: &SemanticContext,
    target: &str,
    expression: &Expr,
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    let Expr::ArgumentRecord { fields } = expression.kind() else {
        return Err(SemanticError {
            code: "E_TEST_ARGUMENT_RECORD",
            message: format!(
                "arguments for `{target}` require a typed record such as `{{ count: 7 }}`; use `{{}}` when it has no parameters"
            ),
        });
    };
    let params = context
        .function_params
        .borrow()
        .get(target)
        .cloned()
        .or_else(|| {
            context
                .external_functions
                .borrow()
                .get(target)
                .map(|signature| signature.params.clone())
        })
        .ok_or_else(|| SemanticError {
            code: "K2002",
            message: format!("unknown test target `{target}`"),
        })?;
    for field in fields {
        if !params.iter().any(|param| param.name == field.name) {
            let suggestion = crate::diagnostic::suggest::closest(
                &field.name,
                params
                    .iter()
                    .filter(|param| !fields.iter().any(|field| field.name == param.name))
                    .map(|param| param.name.as_str()),
            );
            return Err(SemanticError {
                code: "E_TEST_ARGUMENT_RECORD",
                message: format!(
                    "arguments for `{target}`: `{}` is not a parameter{}",
                    field.name,
                    suggestion.map_or_else(String::new, |name| format!("; did you mean `{name}`?"))
                ),
            });
        }
    }
    let declared_fields = params
        .into_iter()
        .map(|param| (param.name, param.ty))
        .collect();
    let typed = analyze_record_fields(
        context,
        target,
        format!("$arguments::{target}"),
        fields,
        declared_fields,
        vars,
    )
    .map_err(|mut error| {
        error.code = match error.code {
            "E_UNKNOWN_STRUCT_FIELD"
            | "E_MISSING_STRUCT_FIELD"
            | "E_DUPLICATE_STRUCT_FIELD"
            | "E_TYPE_ANNOTATION_MISMATCH" => "E_TEST_ARGUMENT_RECORD",
            other => other,
        };
        error.message = format!("arguments for `{target}`: {}", error.message);
        error
    })?;
    context.record_typed_hir_node(expression, &typed.ty)?;
    Ok(typed)
}
fn analyze_invoke_entrypoint_call(
    context: &SemanticContext,
    args: &[Expr],
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    if !current_function_is_test(context) {
        return Err(SemanticError {
            code: "E_TEST_BUILTIN_CONTEXT",
            message: "`test::invoke_kotoage` is available only in #[test] functions and in helpers of a `koto_test` module"
                .into(),
        });
    }
    if args.len() != 2 {
        return Err(SemanticError {
            code: "K2003",
            message: "test::invoke_kotoage expects (string|Name literal, typed argument record)"
                .into(),
        });
    }
    let target_name = invoke_entrypoint_literal(&args[0]).ok_or_else(|| SemanticError {
        code: "E_TEST_ENTRYPOINT_LITERAL",
        message:
            "test::invoke_kotoage requires a literal public or lifecycle target such as \"run\" or Name::parse(\"run\")"
                .into(),
    })?;
    let ret_ty = test_call_target_return_type(context, &target_name, &args[0])?;
    let payload = analyze_test_arguments(context, &target_name, &args[1], vars)?;
    Ok(TypedExpr {
        expr: ExprKind::Call {
            target: CallTarget::Builtin(Builtin::TestInvokeEntrypoint),
            args: vec![typed_string_literal(target_name), payload],
        },
        ty: ret_ty,
    })
}
fn runtime_entrypoint_return_type(
    context: &SemanticContext,
    target_name: &str,
) -> Result<Type, SemanticError> {
    if let Some(modifiers) = context
        .function_modifiers
        .borrow()
        .get(target_name)
        .cloned()
    {
        if !function_is_runtime_entrypoint(&modifiers) {
            return Err(SemanticError {
                code: "E_TEST_ENTRYPOINT_KIND",
                message: format!(
                    "runtime test helpers may only target kotoage/view/hajimari/kaizen declarations, got `{target_name}`"
                ),
            });
        }
        return Ok(context
            .function_returns
            .borrow()
            .get(target_name)
            .cloned()
            .unwrap_or(Type::Unit));
    }
    if let Some(signature) = context
        .external_functions
        .borrow()
        .get(target_name)
        .cloned()
    {
        if !function_is_runtime_entrypoint(&signature.modifiers) {
            return Err(SemanticError {
                code: "E_TEST_ENTRYPOINT_KIND",
                message: format!(
                    "runtime test helpers may only target kotoage/view/hajimari/kaizen declarations, got `{target_name}`"
                ),
            });
        }
        return Ok(signature.return_type);
    }
    Err(SemanticError {
        code: "K2002",
        message: unknown_runtime_target_message(context, target_name),
    })
}
/// Selectors of the kotoage, view, and lifecycle declarations a `test::` helper can call, sorted.
fn declared_runtime_targets(context: &SemanticContext) -> Vec<String> {
    let mut declared = context
        .function_modifiers
        .borrow()
        .iter()
        .filter(|(_, modifiers)| function_is_runtime_entrypoint(modifiers))
        .map(|(name, _)| name.clone())
        .chain(
            context
                .external_functions
                .borrow()
                .iter()
                .filter(|(_, signature)| function_is_runtime_entrypoint(&signature.modifiers))
                .map(|(name, _)| name.clone()),
        )
        .collect::<Vec<_>>();
    declared.sort_unstable();
    declared.dedup();
    declared
}
/// [`runtime_entrypoint_return_type`] for a `test::` helper call: a rejected target is reported
/// at the selector the test wrote, with the callable selectors as help.
fn test_call_target_return_type(
    context: &SemanticContext,
    target_name: &str,
    selector: &Expr,
) -> Result<Type, SemanticError> {
    runtime_entrypoint_return_type(context, target_name).inspect_err(|_| {
        context.capture_help(
            context.expression_source(selector),
            runtime_target_help(&declared_runtime_targets(context)),
        );
    })
}
/// Help for a rejected `test::` helper target: the selectors the seiyaku under test declares.
fn runtime_target_help(declared: &[String]) -> String {
    if declared.is_empty() {
        return "the seiyaku under test declares no kotoage, view, or lifecycle hook, so there is nothing for `test::` call helpers to call".to_owned();
    }
    format!(
        "call a kotoage, view, or lifecycle declaration of the seiyaku under test by its selector: {}; lifecycle hooks are selected as \"hajimari\" and \"kaizen\" whichever spelling declared them",
        declared
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}
/// Explain an unknown `test::invoke_kotoage` target: a lifecycle keyword written as a selector,
/// or the closest declared kotoage, view, or lifecycle declaration.
fn unknown_runtime_target_message(context: &SemanticContext, target_name: &str) -> String {
    let declared = declared_runtime_targets(context);
    // Lifecycle declarations are selected by their canonical selector whichever keyword spelling
    // declared them; the call site names the spelling the test wrote.
    if let Some(keyword) = crate::glossary::by_spelling(target_name)
        && target_name != keyword.romaji
        && declared.iter().any(|name| name == keyword.romaji)
    {
        return format!(
            "`{target_name}` is a lifecycle keyword, not a selector; the `{target_name}` declaration is selected as \"{}\"",
            keyword.romaji
        );
    }
    let mut message = format!(
        "the seiyaku under test has no kotoage, view, or lifecycle declaration named `{target_name}`"
    );
    if let Some(closest) =
        crate::diagnostic::suggest::closest(target_name, declared.iter().map(String::as_str))
    {
        message.push_str(&format!("; did you mean \"{closest}\"?"));
    }
    message
}
fn analyze_invoke_entrypoint_as_call(
    context: &SemanticContext,
    args: &[Expr],
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    if !current_function_is_test(context) {
        return Err(SemanticError {
            code: "E_TEST_BUILTIN_CONTEXT",
            message:
                "`test::invoke_kotoage_as` is available only in #[test] functions and in helpers of a `koto_test` module"
                    .into(),
        });
    }
    if args.len() != 3 {
        return Err(SemanticError {
            code: "K2003",
            message: "test::invoke_kotoage_as expects (string|Name literal actor, string|Name literal kotoage, typed argument record)".into(),
        });
    }
    let actor = invoke_entrypoint_literal(&args[0]).ok_or_else(|| SemanticError {
        code: "E_TEST_ACTOR_LITERAL",
        message: "test::invoke_kotoage_as requires a literal actor alias such as \"issuer\" or Name::parse(\"issuer\")".into(),
    })?;
    let target_name = invoke_entrypoint_literal(&args[1]).ok_or_else(|| SemanticError {
        code: "E_TEST_ENTRYPOINT_LITERAL",
        message: "test::invoke_kotoage_as requires a literal public or lifecycle target such as \"run\" or Name::parse(\"run\")".into(),
    })?;
    let ret_ty = test_call_target_return_type(context, &target_name, &args[1])?;
    let payload = analyze_test_arguments(context, &target_name, &args[2], vars)?;
    Ok(TypedExpr {
        expr: ExprKind::Call {
            target: CallTarget::Builtin(Builtin::TestInvokeEntrypointAs),
            args: vec![
                typed_string_literal(actor),
                typed_string_literal(target_name),
                payload,
            ],
        },
        ty: ret_ty,
    })
}
fn analyze_expect_reject_as_call(
    context: &SemanticContext,
    args: &[Expr],
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    analyze_rejection_expectation_call(context, args, vars, false)
}
fn analyze_rejection_expectation_call(
    context: &SemanticContext,
    args: &[Expr],
    vars: &mut HashMap<String, Type>,
    any: bool,
) -> Result<TypedExpr, SemanticError> {
    if !current_function_is_test(context) {
        return Err(SemanticError {
            code: "E_TEST_BUILTIN_CONTEXT",
            message: "`expect_reject_as` is available only in #[test] functions and in helpers of a `koto_test` module"
                .into(),
        });
    }
    if args.len() != if any { 3 } else { 4 } {
        return Err(SemanticError {
            code: "K2003",
            message: if any {
                "test::expect_any_reject_as expects actor, kotoage, and arguments".into()
            } else {
                "test::expect_reject_as requires actor, kotoage, arguments, and expected".into()
            },
        });
    }
    let actor = invoke_entrypoint_literal(&args[0]).ok_or_else(|| SemanticError {
        code: "E_TEST_ACTOR_LITERAL",
        message:
            "expect_reject_as requires a literal actor alias such as \"issuer\" or Name::parse(\"issuer\")"
                .into(),
    })?;
    let target_name = invoke_entrypoint_literal(&args[1]).ok_or_else(|| SemanticError {
        code: "E_TEST_ENTRYPOINT_LITERAL",
        message:
            "test::expect_reject_as requires a literal public or lifecycle target such as \"run\" or Name::parse(\"run\")"
                .into(),
    })?;
    let _ = test_call_target_return_type(context, &target_name, &args[1])?;
    let payload = analyze_test_arguments(context, &target_name, &args[2], vars)?;
    let expectation = if any {
        crate::testing::RejectionExpectation::Any
    } else if let Expr::Ident(name) = args[3].kind()
        && let Some(selector) = crate::testing::RejectionExpectation::from_selector(name)
    {
        selector
    } else {
        let value = analyze_expr(context, &args[3], vars)?;
        match (&value.ty, value.kind()) {
            (Type::ErrorEnum(descriptor), ExprKind::VariantCode(code)) => {
                crate::testing::RejectionExpectation::Contract { descriptor: descriptor.as_ref().clone(), code: *code }
            }
            _ => return Err(SemanticError {
                code: "E_TEST_REJECTION_EXPECTATION",
                message: "expected must name a nominal error variant or an exact test::Rejection selector".to_owned(),
            }),
        }
    };
    let expected_bytes =
        ivm_abi::codec::encode_canonical_norito(&expectation).map_err(|error| SemanticError {
            code: "E_TEST_REJECTION_EXPECTATION",
            message: format!("cannot encode rejection expectation: {error}"),
        })?;
    Ok(TypedExpr {
        expr: ExprKind::Call {
            target: CallTarget::Builtin(if any {
                Builtin::TestExpectAnyRejectAs
            } else {
                Builtin::TestExpectRejectAs
            }),
            args: vec![
                typed_string_literal(actor),
                typed_string_literal(target_name),
                payload,
                TypedExpr {
                    expr: ExprKind::Bytes(expected_bytes),
                    ty: Type::Bytes,
                },
            ],
        },
        ty: Type::Unit,
    })
}
fn analyze_actor_account_call(
    context: &SemanticContext,
    args: &[Expr],
) -> Result<TypedExpr, SemanticError> {
    if !current_function_is_test(context) {
        return Err(SemanticError {
            code: "E_TEST_BUILTIN_CONTEXT",
            message: "`actor_account` is available only in #[test] functions and in helpers of a `koto_test` module".into(),
        });
    }
    if args.len() != 1 {
        return Err(SemanticError {
            code: "K2003",
            message: "actor_account expects (string|Name literal actor)".into(),
        });
    }
    let actor = invoke_entrypoint_literal(&args[0]).ok_or_else(|| SemanticError {
        code: "E_TEST_ACTOR_LITERAL",
        message:
            "actor_account requires a literal actor alias such as \"issuer\" or Name::parse(\"issuer\")"
                .into(),
    })?;
    Ok(TypedExpr {
        expr: ExprKind::Call {
            target: CallTarget::Builtin(Builtin::TestActorAccount),
            args: vec![typed_string_literal(actor)],
        },
        ty: Type::AccountId,
    })
}
fn analyze_actor_public_key_call(
    context: &SemanticContext,
    args: &[Expr],
) -> Result<TypedExpr, SemanticError> {
    if !current_function_is_test(context) {
        return Err(SemanticError {
            code: "E_TEST_BUILTIN_CONTEXT",
            message: "`actor_public_key` is available only in #[test] functions and in helpers of a `koto_test` module"
                .into(),
        });
    }
    if args.len() != 1 {
        return Err(SemanticError {
            code: "K2003",
            message: "actor_public_key expects (string|Name literal actor)".into(),
        });
    }
    let actor = invoke_entrypoint_literal(&args[0]).ok_or_else(|| SemanticError {
        code: "E_TEST_ACTOR_LITERAL",
        message:
            "actor_public_key requires a literal actor alias such as \"issuer\" or Name::parse(\"issuer\")"
                .into(),
    })?;
    Ok(TypedExpr {
        expr: ExprKind::Call {
            target: CallTarget::Builtin(Builtin::TestActorPublicKey),
            args: vec![typed_string_literal(actor)],
        },
        ty: Type::Bytes,
    })
}
/// Type-check `test::assert(condition, message:)` or `test::assert_eq(actual:, expected:,
/// message:)` and append the compiler-owned assertion site the test runner reports on failure.
///
/// `assert_eq` accepts any pair of values of one equality-comparable type, using the same rules
/// as `==`. The appended site records the call's exact source range, the literal message, and the
/// compared type; test-mode lowering hands it to the host-private assertion syscall only when the
/// assertion fails.
fn analyze_test_assertion_call(
    context: &SemanticContext,
    call: &Expr,
    builtin: Builtin,
    plan: &CallArgumentPlan,
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    use crate::testing::{AssertionKind, AssertionSite};
    validate_builtin_mode(context, builtin)?;
    let args = plan.ordered.as_slice();
    let (kind, mut typed, value_type) = match builtin {
        Builtin::Assert => {
            if !(1..=2).contains(&args.len()) {
                return Err(SemanticError {
                    code: "K2003",
                    message: "test::assert expects (condition: bool[, message: string|int])".into(),
                });
            }
            let condition = analyze_expr_expected(context, &args[0], vars, Some(&Type::Bool))?;
            if resolve_struct_type(&condition.ty) != Type::Bool {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "test::assert expects a bool condition, found `{}`",
                        type_name(&condition.ty)
                    ),
                });
            }
            (AssertionKind::Assert, vec![condition], None)
        }
        _ => {
            if !(2..=3).contains(&args.len()) {
                return Err(SemanticError {
                    code: "K2003",
                    message:
                        "test::assert_eq expects (actual: T, expected: T[, message: string|int])"
                            .into(),
                });
            }
            let mut actual = analyze_expr(context, &args[0], vars)?;
            let context_ty = actual.ty.clone();
            let mut expected = analyze_expr_expected(context, &args[1], vars, Some(&context_ty))?;
            coerce_contextual_numeric_literals(BinaryOp::Eq, None, &mut actual, &mut expected)?;
            let same_type = resolve_struct_type(&actual.ty) == resolve_struct_type(&expected.ty)
                || (is_blob_like(&actual.ty) && is_blob_like(&expected.ty));
            if !same_type {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "test::assert_eq compares `actual` and `expected` of one type, found `{}` and `{}`",
                        type_name(&actual.ty),
                        type_name(&expected.ty)
                    ),
                });
            }
            if !is_eq_comparable_type(&actual.ty) {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "test::assert_eq cannot compare `{}`: the type does not support `==`",
                        type_name(&actual.ty)
                    ),
                });
            }
            let value_type = type_name(&actual.ty);
            (
                AssertionKind::AssertEq,
                vec![actual, expected],
                Some(value_type),
            )
        }
    };
    let message_index = typed.len();
    let mut literal_message = None;
    if let Some(message) = args.get(message_index) {
        let message = analyze_expr(context, message, vars)?;
        if resolve_struct_type(&message.ty) != Type::String && !is_int_like(&message.ty) {
            return Err(SemanticError {
                code: "K2003",
                message: format!(
                    "`{}` expects `message` to be a string or int, found `{}`",
                    builtin.source_name(),
                    type_name(&message.ty)
                ),
            });
        }
        if let ExprKind::String(text) = message.kind() {
            literal_message = Some(text.clone());
        }
        typed.push(message);
    }
    crate::secret::validate_builtin_call(builtin, &typed)?;
    let range = context.expression_source(call);
    let site = AssertionSite {
        kind,
        source_id: range.map_or(0, |range| range.source.0),
        byte_start: range.map_or(0, |range| range.range.start),
        byte_end: range.map_or(0, |range| range.range.end),
        message: literal_message,
        value_type,
    };
    let encoded =
        ivm_abi::codec::encode_canonical_norito(&site).map_err(|error| SemanticError {
            code: "K2003",
            message: format!("cannot encode the assertion site: {error}"),
        })?;
    typed.push(TypedExpr {
        expr: ExprKind::Bytes(encoded),
        ty: Type::Bytes,
    });
    Ok(typed_builtin_call(builtin, typed, Type::Unit))
}
fn analyze_actor_sign_call(
    context: &SemanticContext,
    args: &[Expr],
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    if !current_function_is_test(context) {
        return Err(SemanticError {
            code: "E_TEST_BUILTIN_CONTEXT",
            message: "`actor_sign` is available only in #[test] functions and in helpers of a `koto_test` module".into(),
        });
    }
    if args.len() != 2 {
        return Err(SemanticError {
            code: "K2003",
            message: "actor_sign expects (string|Name literal actor, bytes)".into(),
        });
    }
    let actor = invoke_entrypoint_literal(&args[0]).ok_or_else(|| SemanticError {
        code: "E_TEST_ACTOR_LITERAL",
        message: "actor_sign requires a literal actor alias such as \"issuer\" or Name::parse(\"issuer\")"
            .into(),
    })?;
    let message = analyze_expr(context, &args[1], vars)?;
    if !is_blob_like(&message.ty) {
        return Err(SemanticError {
            code: "K2003",
            message: "actor_sign expects the message as bytes".into(),
        });
    }
    Ok(TypedExpr {
        expr: ExprKind::Call {
            target: CallTarget::Builtin(Builtin::TestActorSign),
            args: vec![typed_string_literal(actor), message],
        },
        ty: Type::Bytes,
    })
}
fn reject_provably_full_push(
    statement: &Statement,
    previous: Option<&TypedStatement>,
) -> Result<(), SemanticError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let TypedStatement::Let {
        name: binding,
        value,
    } = previous.kind()
    else {
        return Ok(());
    };
    let (ExprKind::List(values), Type::List(_, capacity)) =
        (value.kind(), resolve_struct_type(&value.ty))
    else {
        return Ok(());
    };
    if values.len() != usize::from(capacity) {
        return Ok(());
    }
    let Statement::Expr(expression) = statement.kind() else {
        return Ok(());
    };
    let Expr::Call {
        name,
        args,
        implicit_receiver: true,
        ..
    } = expression.kind()
    else {
        return Ok(());
    };
    if name != "push"
        || args.len() != 2
        || !matches!(args[0].kind(), Expr::Ident(name) if name == binding)
        || !matches!(
            args[1].kind(),
            Expr::IntLiteral(_) | Expr::Bool(_) | Expr::String(_)
        )
    {
        return Ok(());
    }
    Err(SemanticError {
        code: "E_LIST_PROVABLY_FULL",
        message: format!(
            "`{binding}` is initialized with all {capacity} slots occupied; `push` would always raise ListError::CapacityExceeded; declare a larger List capacity or handle `try_push`"
        ),
    })
}
#[derive(Clone, Copy, Default)]
struct BlockTailContext<'a> {
    expected: Option<&'a Type>,
    widen: bool,
}
fn analyze_block(
    context: &SemanticContext,
    block: &Block,
    vars: &mut HashMap<String, Type>,
    mutable_bindings: &mut HashSet<String>,
    expected_ret: Option<&Type>,
    tail_context: BlockTailContext<'_>,
    loop_depth: usize,
) -> Result<TypedBlock, SemanticError> {
    let BlockTailContext {
        expected: expected_tail,
        widen: widen_tail,
    } = tail_context;
    let previous_mutable_bindings = context
        .current_mutable_bindings
        .replace(mutable_bindings.clone());
    let result = (|| {
        let _ = loop_depth;
        let mut statements = Vec::new();
        let mut statement_sources = Vec::new();
        for stmt in &block.statements {
            let mut v = match reject_provably_full_push(stmt, statements.last()).and_then(|()| {
                analyze_statement(
                    context,
                    stmt,
                    vars,
                    mutable_bindings,
                    expected_ret,
                    loop_depth,
                )
            }) {
                Ok(statements) => statements,
                Err(error) => {
                    recover_statement_failure(context, stmt, error, vars, mutable_bindings)?;
                    continue;
                }
            };
            let source = context.statement_source(stmt);
            statement_sources.resize(statement_sources.len() + v.len(), source);
            statements.append(&mut v);
        }
        let tail = if let Some(expression) = &block.tail {
            let mut typed =
                analyze_expr_in_context(context, expression, vars, expected_tail, widen_tail)?;
            if let Some(expected) = expected_tail
                && let Err(mut error) = if widen_tail {
                    ensure_boundary_assignable_and_coerce(expected, &mut typed)
                } else {
                    ensure_assignable_and_coerce(expected, &mut typed)
                }
            {
                context.capture_expression_diagnostic(expression, None);
                error.code = "E_TAIL_TYPE_MISMATCH";
                error.message = format!("block tail type mismatch: {}", error.message);
                return Err(error);
            }
            Some(Box::new(typed))
        } else {
            None
        };
        Ok(TypedBlock {
            statements,
            tail,
            provenance: TypedBlockProvenance {
                statements: statement_sources,
                tail: block
                    .tail
                    .as_ref()
                    .and_then(|expression| context.expression_source(expression)),
            },
        })
    })();
    context
        .current_mutable_bindings
        .replace(previous_mutable_bindings);
    result
}
/// Record a failed statement and continue when skipping it cannot cascade.
///
/// Recovery is active only for statement blocks of a function body, never
/// while analyzing an expression (including speculative checks). A statement
/// is skipped only when it introduces no binding, or when it is an annotated
/// `let` whose declared type can still be bound. Anything else ends analysis of
/// the function with the error, as before.
fn recover_statement_failure(
    context: &SemanticContext,
    statement: &Statement,
    error: SemanticError,
    vars: &mut HashMap<String, Type>,
    mutable_bindings: &mut HashSet<String>,
) -> Result<(), SemanticError> {
    if !context.statement_recovery.get()
        || error.code == "K0003"
        || context.recovered_failures.borrow().len() >= MAX_RECOVERED_FAILURES_PER_FUNCTION
    {
        return Err(error);
    }
    let binding = match statement.kind() {
        Statement::Let {
            mutable,
            pat: Pattern::Name(name),
            ty: Some(annotation),
            ..
        } => {
            let pending = context.pending_diagnostic.borrow_mut().take();
            let declared = convert_type_expr(context, annotation)
                .and_then(|ty| resolve_struct_type_with_context(context, &ty));
            context.pending_diagnostic.replace(pending);
            let Ok(declared) = declared else {
                return Err(error);
            };
            Some((name.clone(), declared, *mutable))
        }
        Statement::Let { .. } => return Err(error),
        _ => None,
    };
    let diagnostic = context.take_diagnostic();
    context.required_list_capacity.borrow_mut().take();
    context
        .recovered_failures
        .borrow_mut()
        .push((error, diagnostic));
    if let Some((name, declared, mutable)) = binding
        && name != "_"
    {
        vars.insert(name.clone(), declared);
        if mutable {
            mutable_bindings.insert(name.clone());
            context.current_mutable_bindings.borrow_mut().insert(name);
        }
    }
    Ok(())
}
fn validate_v1_bounded_for_shape(
    context: &SemanticContext,
    init: &Option<Box<Statement>>,
    cond: &Option<Expr>,
    step: &Option<Box<Statement>>,
) -> Result<(), SemanticError> {
    let Some(init) = init.as_deref() else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "only `for item in range(non_negative_literal)` is supported in Kotodama V1"
                .into(),
        });
    };
    let Statement::Let {
        mutable: true,
        pat: Pattern::Name(variable),
        ty: None,
        value,
    } = init.kind()
    else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "only `for item in range(non_negative_literal)` is supported in Kotodama V1"
                .into(),
        });
    };
    if !matches!(value.kind(), Expr::IntLiteral(value) if value.is_zero()) {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "range loops must start from zero".into(),
        });
    }
    let Some(cond) = cond.as_ref() else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "bounded range loop is missing its compiler-proven condition".into(),
        });
    };
    let Expr::Binary {
        op: BinaryOp::Lt,
        left,
        right,
    } = cond.kind()
    else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "bounded range loop is missing its compiler-proven condition".into(),
        });
    };
    let bound = static_integer_constant(context, right).map_err(|_| SemanticError {
        code: "E_UNBOUNDED_LOOP",
        message: "range bound must be a non-negative compile-time integer expression".into(),
    })?;
    if !matches!(left.kind(), Expr::Ident(name) if name == variable)
        || !matches!(bound.kind(), ExprKind::IntLiteral(value) if !value.is_negative())
    {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "range bounds must be non-negative compile-time integer expressions".into(),
        });
    }
    let Some(step) = step.as_deref() else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "bounded range loop is missing its canonical step".into(),
        });
    };
    let Statement::Assign {
        name,
        value: step_value,
    } = step.kind()
    else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "bounded range loop is missing its canonical step".into(),
        });
    };
    let Expr::Binary {
        op: BinaryOp::Add,
        left: step_left,
        right: step_right,
    } = step_value.kind()
    else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "bounded range loop is missing its canonical increment".into(),
        });
    };
    if name != variable
        || !matches!(step_left.kind(), Expr::Ident(name) if name == variable)
        || !matches!(step_right.kind(), Expr::IntLiteral(value) if value == &BigInt::one())
    {
        return Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "range loop control variables cannot be rewritten".into(),
        });
    }
    Ok(())
}
fn analyze_statement(
    context: &SemanticContext,
    stmt: &Statement,
    vars: &mut HashMap<String, Type>,
    mutable_bindings: &mut HashSet<String>,
    expected_ret: Option<&Type>,
    loop_depth: usize,
) -> Result<Vec<TypedStatement>, SemanticError> {
    let result = analyze_statement_inner(
        context,
        stmt,
        vars,
        mutable_bindings,
        expected_ret,
        loop_depth,
    );
    if result.is_err() {
        context.capture_statement_diagnostic(stmt, None);
    }
    result
}
#[expect(
    clippy::too_many_arguments,
    reason = "the struct-pattern variant's parts have no standalone type; the scope pair is shared"
)]
fn analyze_named_struct_binding(
    context: &SemanticContext,
    name: &str,
    fields: &[StructPatternField],
    rest: bool,
    mutable: bool,
    expr: TypedExpr,
    vars: &mut HashMap<String, Type>,
    mutable_bindings: &mut HashSet<String>,
) -> Result<Vec<TypedStatement>, SemanticError> {
    let Type::Struct {
        name: actual_name,
        fields: declared_fields,
    } = resolve_struct_type(&expr.ty)
    else {
        return Err(SemanticError {
            code: "E_STRUCT_PATTERN_TYPE",
            message: format!("pattern `{name}` requires a struct value"),
        });
    };
    let expected_name = context
        .resolved_named_types
        .borrow()
        .get(name)
        .and_then(|ty| match ty {
            Type::Struct { name, .. } => Some(name.clone()),
            _ => None,
        })
        .unwrap_or_else(|| name.to_owned());
    if actual_name != expected_name {
        return Err(SemanticError {
            code: "E_STRUCT_PATTERN_TYPE",
            message: format!("pattern `{name}` cannot destructure `{actual_name}`"),
        });
    }
    let mut seen_fields = HashSet::new();
    let mut seen_bindings = HashSet::new();
    for field in fields {
        let error = if !seen_fields.insert(field.name.as_str()) {
            Some(SemanticError {
                code: "E_DUPLICATE_STRUCT_PATTERN_FIELD",
                message: format!(
                    "field `{}` occurs more than once in the pattern",
                    field.name
                ),
            })
        } else if !declared_fields.iter().any(|(name, _)| name == &field.name) {
            Some(SemanticError {
                code: "E_UNKNOWN_STRUCT_FIELD",
                message: format!("struct `{name}` has no field `{}`", field.name),
            })
        } else {
            None
        };
        if let Some(error) = error {
            let suggestion = (error.code == "E_UNKNOWN_STRUCT_FIELD")
                .then(|| {
                    crate::diagnostic::suggest::closest(
                        &field.name,
                        declared_fields
                            .iter()
                            .map(|(declared, _)| declared.as_str()),
                    )
                })
                .flatten();
            match (suggestion, field.source) {
                (Some(suggestion), Some(source)) => context.capture_structured(
                    crate::semantic_diagnostics::SemanticDiagnostic::at(
                        source,
                        Some(crate::semantic_diagnostics::SemanticFix::Replace {
                            replacement: suggestion.to_owned(),
                        }),
                    )
                    .with_help(format!("did you mean `{suggestion}`?")),
                ),
                _ => context.capture_diagnostic(field.source, None),
            }
            return Err(error);
        }
        if field.binding != "_" {
            ensure_new_local_binding(context, &field.binding, vars)?;
            if !seen_bindings.insert(field.binding.as_str()) {
                return Err(SemanticError {
                    code: "K2001",
                    message: format!("duplicate binding `{}` in struct pattern", field.binding),
                });
            }
        }
    }
    if !rest {
        let missing = declared_fields
            .iter()
            .filter(|(field, _)| !seen_fields.contains(field.as_str()))
            .map(|(field, _)| field.as_str())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(SemanticError {
                code: "E_MISSING_STRUCT_PATTERN_FIELD",
                message: format!(
                    "struct pattern omits {}; bind them or explicitly discard unspecified fields with `..`",
                    missing.join(", ")
                ),
            });
        }
    }
    let capture = context.fresh_aggregate_capture();
    let captured = TypedExpr {
        expr: ExprKind::Ident(capture.clone()),
        ty: expr.ty.clone(),
    };
    vars.insert(capture.clone(), expr.ty.clone());
    let mut output = vec![TypedStatement::Let {
        name: capture,
        value: expr,
    }];
    for field in fields {
        if field.binding == "_" {
            continue;
        }
        let (index, (_, ty)) = declared_fields
            .iter()
            .enumerate()
            .find(|(_, (name, _))| name == &field.name)
            .expect("field existence validated");
        let value = TypedExpr {
            expr: ExprKind::Member {
                object: Box::new(captured.clone()),
                field: index.to_string(),
            },
            ty: resolve_struct_type(ty),
        };
        vars.insert(field.binding.clone(), value.ty.clone());
        if mutable {
            mutable_bindings.insert(field.binding.clone());
            context
                .current_mutable_bindings
                .borrow_mut()
                .insert(field.binding.clone());
        }
        output.push(TypedStatement::Let {
            name: field.binding.clone(),
            value: value.clone(),
        });
        bind_tuple_fields_rec(&mut output, vars, &field.binding, &value, &value.ty);
        bind_struct_fields_rec(&mut output, vars, &field.binding, &value, &value.ty);
    }
    Ok(output)
}
fn analyze_binding_pattern(
    context: &SemanticContext,
    pat: &Pattern,
    mutable: bool,
    expr: TypedExpr,
    vars: &mut HashMap<String, Type>,
    mutable_bindings: &mut HashSet<String>,
) -> Result<Vec<TypedStatement>, SemanticError> {
    match pat {
        Pattern::Name(name) => {
            if name == "_" {
                return Ok(vec![TypedStatement::Let {
                    name: name.clone(),
                    value: expr,
                }]);
            }
            ensure_new_local_binding(context, name, vars)?;
            // Bind the name and, if it's a tuple, also synthesize per-field bindings name#i.
            let mut out = Vec::new();
            vars.insert(name.clone(), expr.ty.clone());
            if mutable {
                mutable_bindings.insert(name.clone());
                context
                    .current_mutable_bindings
                    .borrow_mut()
                    .insert(name.clone());
            }
            out.push(TypedStatement::Let {
                name: name.clone(),
                value: expr.clone(),
            });
            match &expr.ty {
                Type::Tuple(_) => {
                    bind_tuple_fields_rec(&mut out, vars, name, &expr, &expr.ty);
                }
                Type::Struct { fields, .. } => {
                    for (i, (_fname, fty)) in fields.iter().enumerate() {
                        let val_expr = TypedExpr {
                            expr: ExprKind::Member {
                                object: Box::new(TypedExpr {
                                    expr: ExprKind::Ident(name.clone()),
                                    ty: expr.ty.clone(),
                                }),
                                field: i.to_string(),
                            },
                            ty: fty.clone(),
                        };
                        let sname = format!("{name}#{i}");
                        let field_ty = resolve_struct_type(fty);
                        vars.insert(sname.clone(), field_ty.clone());
                        out.push(TypedStatement::Let {
                            name: sname.clone(),
                            value: val_expr.clone(),
                        });
                        bind_struct_fields_rec(&mut out, vars, &sname, &val_expr, &field_ty);
                    }
                }
                _ => {}
            }
            Ok(out)
        }
        Pattern::Tuple(names) => {
            let mut out = Vec::new();
            for name in names.iter() {
                if name != "_" {
                    ensure_new_local_binding(context, name, vars)?;
                }
            }
            let mut unique_names = HashSet::new();
            for name in names {
                if name != "_" && !unique_names.insert(name) {
                    return Err(SemanticError {
                        code: "K2001",
                        message: format!("duplicate binding `{name}` in destructuring declaration"),
                    });
                }
            }
            match &expr.ty {
                Type::Tuple(ts) => {
                    if names.len() != ts.len() {
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "tuple destructuring expects {} bindings, got {}",
                                ts.len(),
                                names.len()
                            ),
                        });
                    }
                    let capture_name = context.fresh_aggregate_capture();
                    let captured = TypedExpr {
                        expr: ExprKind::Ident(capture_name.clone()),
                        ty: expr.ty.clone(),
                    };
                    vars.insert(capture_name.clone(), expr.ty.clone());
                    out.push(TypedStatement::Let {
                        name: capture_name,
                        value: expr.clone(),
                    });
                    // Destructure by emitting member-access typed expressions for each field.
                    for (i, name) in names.iter().enumerate() {
                        let ti = ts.get(i).cloned().expect("tuple arity already validated");
                        let member = TypedExpr {
                            expr: ExprKind::Member {
                                object: Box::new(captured.clone()),
                                field: i.to_string(),
                            },
                            ty: ti.clone(),
                        };
                        if name != "_" {
                            vars.insert(name.clone(), ti.clone());
                            if mutable {
                                mutable_bindings.insert(name.clone());
                                context
                                    .current_mutable_bindings
                                    .borrow_mut()
                                    .insert(name.clone());
                            }
                        }
                        out.push(TypedStatement::Let {
                            name: name.clone(),
                            value: member,
                        });
                    }
                }
                Type::Struct { name, .. } => {
                    return Err(SemanticError {
                        code: "E_POSITIONAL_STRUCT_PATTERN",
                        message: format!(
                            "struct `{name}` requires a named pattern: `let {name} {{ field, .. }} = value;`"
                        ),
                    });
                }
                _ => {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "tuple destructuring expects a tuple".into(),
                    });
                }
            }
            Ok(out)
        }
        Pattern::Struct { name, fields, rest } => analyze_named_struct_binding(
            context,
            name,
            fields,
            *rest,
            mutable,
            expr,
            vars,
            mutable_bindings,
        ),
    }
}
fn analyze_statement_inner(
    context: &SemanticContext,
    stmt: &Statement,
    vars: &mut HashMap<String, Type>,
    mutable_bindings: &mut HashSet<String>,
    expected_ret: Option<&Type>,
    loop_depth: usize,
) -> Result<Vec<TypedStatement>, SemanticError> {
    let _ = loop_depth;
    let kind = stmt.kind();
    let statement_node = context.validate_statement_node(stmt)?;
    if !matches!(kind, Statement::Assign { .. })
        && statement_node
            .as_ref()
            .is_some_and(|node| node.target.is_some())
    {
        return Err(SemanticError {
            code: "E_INTERNAL_RESOLUTION",
            message: "non-assignment statement carries a resolver assignment target".into(),
        });
    }
    match kind {
        Statement::Source { .. } | Statement::Resolved { .. } => {
            unreachable!("kind() strips AST and resolved-HIR provenance wrappers")
        }
        Statement::Let {
            mutable,
            pat,
            ty,
            value,
        } => {
            if ty.is_none()
                && let Pattern::Name(name) = pat
                && name != "_"
                && let Some(source) = context.statement_source(stmt)
            {
                context
                    .inferred_locals
                    .borrow_mut()
                    .insert(name.clone(), source);
            }
            let declared = ty
                .as_ref()
                .map(|annotation| convert_type_expr(context, annotation))
                .transpose()?
                .map(|ty| resolve_struct_type_with_context(context, &ty))
                .transpose()?;
            let mut expr = match analyze_expr_expected(context, value, vars, declared.as_ref()) {
                Ok(expression) => expression,
                Err(error) => {
                    if error.code == "E_LIST_COMPREHENSION_CAPACITY"
                        && matches!(value.kind(), Expr::ListComprehension { .. })
                        && let (Some(annotation), Some(Type::List(element, _)), Some(capacity)) = (
                            ty.as_ref(),
                            declared.as_ref(),
                            context.required_list_capacity.borrow_mut().take(),
                        )
                    {
                        let replacement =
                            render_source_type_name(&Type::List(element.clone(), capacity));
                        context.replace_diagnostic(
                            context.type_source(annotation),
                            Some(crate::semantic_diagnostics::SemanticFix::Replace { replacement }),
                        );
                    }
                    return Err(error);
                }
            };
            if let Some(dt) = &declared
                && let Err(mut error) = ensure_assignable_and_coerce(dt, &mut expr)
            {
                if error.code == "E_TYPE_ANNOTATION_MISMATCH" {
                    error.message = format!("type annotation mismatch: {}", error.message);
                }
                if error.code == "E_QUERY_RESULT_TYPE"
                    && let Some(annotation) = ty.as_ref()
                {
                    context.replace_diagnostic(
                        context.type_source(annotation),
                        Some(crate::semantic_diagnostics::SemanticFix::Replace {
                            replacement: render_source_type_name(&expr.ty),
                        }),
                    );
                }
                return Err(error);
            }
            if is_state_map_expr(context, &expr) {
                return Err(SemanticError {
                    code: "E_STATE_MAP_ALIAS",
                    message: "state maps are not first-class; use the state identifier directly."
                        .into(),
                });
            }
            analyze_binding_pattern(context, pat, *mutable, expr, vars, mutable_bindings)
        }
        Statement::Assign { name, value } => {
            context.validate_assignment_target(statement_node.as_ref(), name)?;
            // Must exist
            let expected = vars.get(name).cloned().ok_or_else(|| SemanticError {
                code: "K2002",
                message: format!("undefined variable {name}"),
            })?;
            if is_state_binding(context, name)
                && matches!(resolve_struct_type(&expected), Type::StateMap(_, _))
            {
                return Err(SemanticError {
                    code: "E_STATE_MAP_ALIAS",
                    message: "state maps cannot be reassigned; use map indexing.".into(),
                });
            }
            ensure_mutable_assignment_target(context, name, mutable_bindings)?;
            let mut expr = analyze_expr_expected(context, value, vars, Some(&expected))?;
            if is_state_binding(context, name) {
                crate::secret::reject_secret_state_value(&expr)?;
            }
            if is_state_map_expr(context, &expr) {
                return Err(SemanticError {
                    code: "E_STATE_MAP_ALIAS",
                    message: "state maps are not first-class; use the state identifier directly."
                        .into(),
                });
            }

            inferred_assignment(context, stmt, name, &expected, &mut expr)?;
            // Rebind SSA name to new value
            vars.insert(name.clone(), expr.ty.clone());
            let mut out = Vec::new();
            out.push(TypedStatement::Let {
                name: name.clone(),
                value: expr.clone(),
            });
            if !is_state_binding(context, name) {
                bind_tuple_fields_rec(&mut out, vars, name, &expr, &expr.ty);
                bind_struct_fields_rec(&mut out, vars, name, &expr, &expr.ty);
            }
            Ok(out)
        }
        Statement::AssignExpr { target, op, value } => {
            // support map indexing and simple variable rebinding
            match target.kind() {
                Expr::Member { .. } => {
                    let mut root = target;
                    while let Expr::Member { object, .. } = root.kind() {
                        root = object;
                    }
                    let Expr::Ident(root_name) = root.kind() else {
                        return Err(SemanticError {
                            code: "E_INVALID_ASSIGNMENT_TARGET",
                            message: "field assignment must be rooted in a mutable binding".into(),
                        });
                    };
                    ensure_mutable_assignment_target(context, root_name, mutable_bindings)?;
                    let target = analyze_expr(context, target, vars)?;
                    let mut replacement =
                        analyze_expr_expected(context, value, vars, Some(&target.ty))?;
                    if let Some(binary) = assign_op_to_binary(*op) {
                        let mut left = target.clone();
                        coerce_contextual_numeric_literals(
                            binary,
                            Some(&target.ty),
                            &mut left,
                            &mut replacement,
                        )?;
                        reject_implicit_int_decimal_mix(&left.ty, &replacement.ty)?;
                        let Some(ty) = arithmetic_result_type(binary, &left.ty, &replacement.ty)
                        else {
                            context.capture_help(
                                context.statement_source(stmt),
                                type_help::operator_help(binary, &left.ty, &replacement.ty),
                            );
                            return Err(SemanticError {
                                code: "K2003",
                                message: type_help::operator_message(
                                    type_help::assign_symbol(*op),
                                    &left.ty,
                                    &replacement.ty,
                                ),
                            });
                        };
                        replacement = TypedExpr {
                            expr: ExprKind::Binary {
                                op: binary,
                                left: Box::new(left),
                                right: Box::new(replacement),
                            },
                            ty,
                        };
                    }
                    ensure_assignable_and_coerce(&target.ty, &mut replacement)?;
                    if is_state_binding(context, root_name) {
                        crate::secret::reject_secret_state_value(&replacement)?;
                    }
                    let capture = context.fresh_aggregate_capture();
                    let captured = TypedExpr {
                        expr: ExprKind::Ident(capture.clone()),
                        ty: replacement.ty.clone(),
                    };
                    let (name, rebuilt) = rebuild_assigned_product(&target, captured)?;
                    let mut out = vec![
                        TypedStatement::Let {
                            name: capture,
                            value: replacement,
                        },
                        TypedStatement::Let {
                            name: name.clone(),
                            value: rebuilt.clone(),
                        },
                    ];
                    if !is_state_binding(context, &name) {
                        bind_tuple_fields_rec(&mut out, vars, &name, &rebuilt, &rebuilt.ty);
                        bind_struct_fields_rec(&mut out, vars, &name, &rebuilt, &rebuilt.ty);
                    }
                    Ok(out)
                }
                Expr::Index { target: map, index } => {
                    let map_t = analyze_expr(context, map, vars)?;
                    let mut key_t = analyze_expr(context, index, vars)?;
                    crate::secret::reject_secret_key(&key_t)?;
                    match map_t.ty.clone() {
                        Type::StateMap(k, v) => {
                            ensure_assignable_and_coerce(&k, &mut key_t)?;
                            ensure_in_memory_map_word_types(context, &map_t)?;
                            if *op == AssignOp::Set {
                                let mut val_t =
                                    analyze_expr_expected(context, value, vars, Some(&v))?;
                                crate::secret::reject_secret_state_value(&val_t)?;
                                ensure_assignable_and_coerce(&v, &mut val_t)?;
                                return Ok(vec![TypedStatement::MapSet {
                                    map: map_t,
                                    key: key_t,
                                    value: Box::new(val_t),
                                }]);
                            }
                            Err(SemanticError {
                                code: "E_STATE_MAP_OPTIONAL_READ",
                                message: "compound StateMap assignment reads a possibly absent key; use `map.get(key)` and handle Option<V> before assigning with `map[key] = value`"
                                .into(),
                            })
                        }
                        Type::List(element, _) => {
                            let receiver_is_mutable = matches!(map.kind(), Expr::Ident(name) if mutable_bindings.contains(name));
                            let fix = if *op == AssignOp::Set
                                && receiver_is_mutable
                                && resolve_struct_type(&key_t.ty) == Type::Int
                                && context.expression_is_assignable(value, vars, &element)
                            {
                                match (
                                    context.expression_source(map),
                                    context.expression_source(index),
                                    context.expression_source(value),
                                ) {
                                    (Some(target), Some(index), Some(value)) => {
                                        Some(crate::semantic_diagnostics::SemanticFix::ListSet {
                                            target,
                                            index,
                                            value,
                                        })
                                    }
                                    _ => None,
                                }
                            } else {
                                None
                            };
                            context.capture_statement_diagnostic(stmt, fix);
                            Err(SemanticError {
                                code: "E_LIST_UNSAFE_INDEX",
                                message: "indexed List assignment is unsupported; use `list.set(index: index, value: value)` for a checked write that reverts on failure"
                                    .into(),
                            })
                        }
                        other => Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "map assignment expects StateMap<K,V> target, got {}",
                                type_name(&other)
                            ),
                        }),
                    }
                }
                Expr::Ident(name) => {
                    context.validate_value_target(target, name, vars)?;
                    // Simple compound assignment lowering: rebind SSA name
                    let expected = vars.get(name).cloned().ok_or_else(|| SemanticError {
                        code: "K2002",
                        message: format!("undefined variable {name}"),
                    })?;
                    if is_state_binding(context, name)
                        && matches!(resolve_struct_type(&expected), Type::StateMap(_, _))
                    {
                        return Err(SemanticError {
                            code: "E_STATE_MAP_ALIAS",
                            message: "state maps cannot be reassigned; use map indexing.".into(),
                        });
                    }
                    ensure_mutable_assignment_target(context, name, mutable_bindings)?;
                    let mut expr = if *op == AssignOp::Set {
                        analyze_expr_expected(context, value, vars, Some(&expected))?
                    } else {
                        analyze_expr(context, value, vars)?
                    };
                    if is_state_binding(context, name) {
                        crate::secret::reject_secret_state_value(&expr)?;
                    }
                    if is_state_map_expr(context, &expr) {
                        return Err(SemanticError {
                            code: "E_STATE_MAP_ALIAS",
                            message:
                                "state maps are not first-class; use the state identifier directly."
                                    .into(),
                        });
                    }

                    if *op == AssignOp::Set {
                        inferred_assignment(context, stmt, name, &expected, &mut expr)?;
                        vars.insert(name.clone(), expr.ty.clone());
                        let mut out = Vec::new();
                        out.push(TypedStatement::Let {
                            name: name.clone(),
                            value: expr.clone(),
                        });
                        if !is_state_binding(context, name) {
                            bind_tuple_fields_rec(&mut out, vars, name, &expr, &expr.ty);
                            bind_struct_fields_rec(&mut out, vars, name, &expr, &expr.ty);
                        }
                        return Ok(out);
                    }
                    let bin_op = assign_op_to_binary(*op).expect("compound op maps to binary op");
                    let mut left = TypedExpr {
                        expr: ExprKind::Ident(name.clone()),
                        ty: expected.clone(),
                    };
                    coerce_contextual_numeric_literals(
                        bin_op,
                        Some(&expected),
                        &mut left,
                        &mut expr,
                    )?;
                    reject_implicit_int_decimal_mix(&left.ty, &expr.ty)?;
                    let Some(result_ty) = arithmetic_result_type(bin_op, &left.ty, &expr.ty) else {
                        if let Some(primary) = context.statement_source(stmt) {
                            let mut diagnostic =
                                crate::semantic_diagnostics::SemanticDiagnostic::at(primary, None)
                                    .with_help(type_help::operator_help(
                                        bin_op, &left.ty, &expr.ty,
                                    ));
                            diagnostic
                                .labels
                                .extend(context.inferred_local_label(name, &expected));
                            context.capture_structured(diagnostic);
                        }
                        return Err(SemanticError {
                            code: "K2003",
                            message: type_help::operator_message(
                                type_help::assign_symbol(*op),
                                &left.ty,
                                &expr.ty,
                            ),
                        });
                    };
                    if resolve_struct_type(&result_ty) != resolve_struct_type(&expected) {
                        if let Some(primary) = context.statement_source(stmt) {
                            let mut diagnostic =
                                crate::semantic_diagnostics::SemanticDiagnostic::at(primary, None)
                                    .with_help(format!(
                                        "Assign the result to a binding of type {}, or convert it explicitly.",
                                        type_help::quoted(&result_ty)
                                    ));
                            diagnostic
                                .labels
                                .extend(context.inferred_local_label(name, &expected));
                            context.capture_structured(diagnostic);
                        }
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "`{name} {} ...` produces {}, which cannot be stored in `{name}` of type {}",
                                type_help::assign_symbol(*op),
                                type_help::quoted(&result_ty),
                                type_help::quoted(&expected),
                            ),
                        });
                    }
                    let value_expr = TypedExpr {
                        expr: ExprKind::Binary {
                            op: bin_op,
                            left: Box::new(left),
                            right: Box::new(expr),
                        },
                        ty: result_ty,
                    };
                    vars.insert(name.clone(), value_expr.ty.clone());
                    let mut out = Vec::new();
                    out.push(TypedStatement::Let {
                        name: name.clone(),
                        value: value_expr.clone(),
                    });
                    bind_tuple_fields_rec(&mut out, vars, name, &value_expr, &value_expr.ty);
                    Ok(out)
                }
                _ => Err(SemanticError {
                    code: "E_INVALID_ASSIGNMENT_TARGET",
                    message: "assignment target must be a variable, product field, or map index"
                        .into(),
                }),
            }
        }
        Statement::Emit(expression) => {
            let payload = analyze_record_literal(context, expression, vars, true)?;
            context.record_typed_hir_node(expression, &payload.ty)?;
            let Expr::StructLiteral { name, .. } = expression.kind() else {
                unreachable!("checked event record")
            };
            let ordinal = context
                .event_names
                .borrow()
                .iter()
                .position(|event| event == name)
                .expect("checked declared event");
            Ok(vec![TypedStatement::Expr(TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Intrinsic(CompilerIntrinsic::EmitEvent),
                    args: vec![
                        TypedExpr {
                            expr: ExprKind::IntLiteral(BigInt::from(ordinal as u64)),
                            ty: Type::Int,
                        },
                        payload,
                    ],
                },
                ty: Type::Unit,
            })])
        }
        Statement::Expr(e) => Ok(vec![TypedStatement::Expr(analyze_expr(context, e, vars)?)]),
        Statement::Return(opt) => {
            let mut tv = if let Some(e) = opt {
                Some(analyze_expr_in_context(
                    context,
                    e,
                    vars,
                    expected_ret,
                    true,
                )?)
            } else {
                None
            };
            if expected_ret.is_none() {
                if tv.is_some() {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "returning a value requires a declared return type".into(),
                    });
                }
            } else if let Some(exp) = expected_ret {
                match tv.as_mut() {
                    None => {
                        if !matches!(exp, Type::Unit) {
                            return Err(SemanticError {
                                code: "K2003",
                                message: "return type mismatch: expected value".into(),
                            });
                        }
                    }
                    Some(expr) => {
                        if let Err(mut err) = ensure_boundary_assignable_and_coerce(exp, expr) {
                            err.code = "E_RETURN_TYPE_MISMATCH";
                            err.message = format!("return type mismatch: {}", err.message);
                            if let Some(primary) = context.statement_source(stmt) {
                                context.capture_structured(
                                    crate::semantic_diagnostics::SemanticDiagnostic::at(
                                        primary, None,
                                    )
                                    .with_label(
                                        *context.current_return_source.borrow(),
                                        format!(
                                            "the function declares return type {} here",
                                            type_help::quoted(exp)
                                        ),
                                    ),
                                );
                            }
                            return Err(err);
                        }
                    }
                }
            }
            Ok(vec![TypedStatement::Return(tv)])
        }
        Statement::Break => {
            if loop_depth == 0 {
                return Err(SemanticError {
                    code: "E_BREAK_OUTSIDE_LOOP",
                    message: "`break` must appear inside a loop".into(),
                });
            }
            Ok(vec![TypedStatement::Break])
        }
        Statement::Continue => {
            if loop_depth == 0 {
                return Err(SemanticError {
                    code: "E_CONTINUE_OUTSIDE_LOOP",
                    message: "`continue` must appear inside a loop".into(),
                });
            }
            Ok(vec![TypedStatement::Continue])
        }
        Statement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            let cond_t = analyze_expr(context, cond, vars)?;
            crate::secret::reject_secret_control_flow(&cond_t)?;
            if cond_t.ty != Type::Bool {
                return Err(SemanticError {
                    code: "K2003",
                    message: "if condition must be bool".into(),
                });
            }
            let then_block = analyze_block(
                context,
                then_branch,
                &mut vars.clone(),
                &mut mutable_bindings.clone(),
                expected_ret,
                BlockTailContext::default(),
                loop_depth,
            )?;
            let else_block = if let Some(b) = else_branch {
                Some(analyze_block(
                    context,
                    b,
                    &mut vars.clone(),
                    &mut mutable_bindings.clone(),
                    expected_ret,
                    BlockTailContext::default(),
                    loop_depth,
                )?)
            } else {
                None
            };
            Ok(vec![TypedStatement::If {
                cond: cond_t,
                then_branch: then_block,
                else_branch: else_block,
            }])
        }
        Statement::IfLet {
            pattern,
            value,
            then_branch,
            else_branch,
        } => {
            let value = analyze_expr(context, value, vars)?;
            let (pattern, binding) = analyze_sum_pattern(context, pattern, &value.ty)?;
            let mut then_vars = vars.clone();
            if let Some((name, ty)) = binding {
                ensure_new_local_binding(context, &name, &then_vars)?;
                then_vars.insert(name, ty);
            }
            let then_branch = analyze_block(
                context,
                then_branch,
                &mut then_vars,
                &mut mutable_bindings.clone(),
                expected_ret,
                BlockTailContext::default(),
                loop_depth,
            )?;
            let else_branch = if let Some(block) = else_branch {
                Some(analyze_block(
                    context,
                    block,
                    &mut vars.clone(),
                    &mut mutable_bindings.clone(),
                    expected_ret,
                    BlockTailContext::default(),
                    loop_depth,
                )?)
            } else {
                None
            };
            Ok(vec![TypedStatement::IfLet {
                pattern,
                value,
                then_branch,
                else_branch,
            }])
        }
        Statement::While { .. } => Err(SemanticError {
            code: "E_UNBOUNDED_LOOP",
            message: "`while` is not part of Kotodama V1; use a compiler-proven bounded `for` loop"
                .into(),
        }),
        Statement::For {
            line,
            init,
            cond,
            step,
            body,
        } => {
            validate_v1_bounded_for_shape(context, init, cond, step)?;
            let mut local = vars.clone();
            let mut local_mutable_bindings = mutable_bindings.clone();
            let init_t = if let Some(s) = init {
                let mut v = analyze_statement(
                    context,
                    s,
                    &mut local,
                    &mut local_mutable_bindings,
                    expected_ret,
                    loop_depth,
                )?;
                if v.len() != 1 {
                    return Err(SemanticError {
                        code: "E_FOR_INITIALIZER",
                        message: "for-loop initializer must be a simple let or expression".into(),
                    });
                }
                Some(Box::new(v.remove(0)))
            } else {
                None
            };
            let loop_env = local.clone();
            let cond_t = if let Some(c) = cond {
                let mut cond_vars = loop_env.clone();
                let mut t = analyze_expr(context, c, &mut cond_vars)?;
                if let Expr::Binary {
                    right: source_bound,
                    ..
                } = c.kind()
                    && let ExprKind::Binary { right, .. } = &mut t.expr
                {
                    **right = static_integer_constant(context, source_bound)?;
                }
                crate::secret::reject_secret_control_flow(&t)?;
                if t.ty != Type::Bool {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "for condition must be bool".into(),
                    });
                }
                Some(t)
            } else {
                None
            };
            let step_t = if let Some(s) = step {
                let mut step_vars = loop_env.clone();
                let mut v = analyze_statement(
                    context,
                    s,
                    &mut step_vars,
                    &mut local_mutable_bindings.clone(),
                    expected_ret,
                    loop_depth + 1,
                )?;
                if v.len() != 1 {
                    return Err(SemanticError {
                        code: "E_FOR_STEP",
                        message: "for-loop step must be a simple let or expression".into(),
                    });
                }
                Some(Box::new(v.remove(0)))
            } else {
                None
            };
            let body_t = analyze_block(
                context,
                body,
                &mut loop_env.clone(),
                &mut local_mutable_bindings.clone(),
                expected_ret,
                BlockTailContext::default(),
                loop_depth + 1,
            )?;
            Ok(vec![TypedStatement::For {
                line: *line,
                init: init_t,
                cond: cond_t,
                step: step_t,
                body: body_t,
            }])
        }
        Statement::ForEachMap { pat, map, body } => {
            let list = analyze_expr(context, map, &mut vars.clone())?;
            let Type::List(element, _) = resolve_struct_type(&list.ty) else {
                return Err(SemanticError { code: "E_UNBOUNDED_ITERATION", message: "for iteration requires a bounded List; use StateMap.take(N) or StateMap.page(after: cursor, limit: N).items".into() });
            };
            let item = context.fresh_aggregate_capture();
            let mut local_vars = vars.clone();
            local_vars.insert(item.clone(), element.as_ref().clone());
            let mut local_mutability = mutable_bindings.clone();
            let bindings = analyze_binding_pattern(
                context,
                pat,
                false,
                TypedExpr {
                    expr: ExprKind::Ident(item.clone()),
                    ty: *element,
                },
                &mut local_vars,
                &mut local_mutability,
            )?;
            let mut body_t = analyze_block(
                context,
                body,
                &mut local_vars,
                &mut local_mutability,
                expected_ret,
                BlockTailContext::default(),
                loop_depth + 1,
            )?;
            body_t.prepend_unsourced(bindings);
            Ok(vec![TypedStatement::ForEachMap {
                key: item,
                value: None,
                map: list,
                body: body_t,
            }])
        }
    }
}
fn query_helper_accepts_arg(builtin: Builtin, ty: &Type) -> bool {
    match builtin {
        Builtin::QueryExecuteNorito
        | Builtin::QueryGetContractManifest
        | Builtin::ZkRootsGet
        | Builtin::ZkVoteGetTally => is_blob_like(ty),
        Builtin::QueryGetAccount => matches!(ty, Type::AccountId),
        Builtin::QueryGetAsset => matches!(ty, Type::AssetId),
        Builtin::QueryGetAssetDefinition => matches!(ty, Type::AssetDefinitionId),
        Builtin::QueryGetDomain => matches!(ty, Type::DomainId),
        Builtin::QueryGetNft => matches!(ty, Type::NftId),
        Builtin::QueryGetParameter => matches!(ty, Type::Name) || is_blob_like(ty),
        Builtin::QueryGetContractInstance => matches!(ty, Type::Name) || is_blob_like(ty),
        _ => false,
    }
}
fn core_query_view_type(builtin: Builtin) -> Option<Type> {
    let (name, fields) = match builtin {
        Builtin::QueryGetAccount | Builtin::QueryPageAccounts => (
            "AccountView",
            vec![("id", Type::AccountId), ("metadata", Type::Json)],
        ),
        Builtin::QueryGetAsset | Builtin::QueryPageAssets | Builtin::QueryPageAssetsOf => (
            "AssetView",
            vec![("id", Type::AssetId), ("amount", Type::Quantity)],
        ),
        Builtin::QueryGetAssetDefinition | Builtin::QueryPageAssetDefinitions => (
            "AssetDefinitionView",
            vec![
                ("id", Type::AssetDefinitionId),
                ("name", Type::String),
                ("description", Type::Option(Box::new(Type::String))),
                ("owned_by", Type::AccountId),
                ("total_quantity", Type::Quantity),
                ("numeric_scale", Type::Option(Box::new(Type::Int))),
                ("metadata", Type::Json),
            ],
        ),
        Builtin::QueryGetDomain | Builtin::QueryPageDomains => (
            "DomainView",
            vec![
                ("id", Type::DomainId),
                ("owned_by", Type::AccountId),
                ("metadata", Type::Json),
            ],
        ),
        Builtin::QueryGetNft | Builtin::QueryPageNfts => (
            "NftView",
            vec![
                ("id", Type::NftId),
                ("owned_by", Type::AccountId),
                ("content", Type::Json),
            ],
        ),
        _ => return None,
    };
    Some(Type::Struct {
        name: format!("kotodama::{name}"),
        fields: Arc::from(
            fields
                .into_iter()
                .map(|(field, ty)| (field.to_owned(), ty))
                .collect::<Vec<_>>(),
        ),
    })
}
fn state_page_type(key: Type, value: Type, capacity: u8) -> Result<Type, SemanticError> {
    if !is_supported_durable_key_type(&key) || !is_supported_durable_value_type(&value) {
        return Err(SemanticError {
            code: "K2003",
            message: "StatePage requires canonical durable StateMap key and value types".into(),
        });
    }
    let ty = Type::Struct {
        name: "kotodama::StatePage".into(),
        fields: Arc::from(vec![
            (
                "items".into(),
                Type::List(Box::new(Type::Tuple(vec![key.clone(), value])), capacity),
            ),
            (
                "next".into(),
                Type::Option(Box::new(Type::StateCursor(Box::new(key)))),
            ),
        ]),
    };

    Ok(ty)
}
fn state_page_components(ty: &Type) -> Option<(&Type, &Type, u8)> {
    let Type::Struct { name, fields } = ty else {
        return None;
    };
    if name != "kotodama::StatePage" {
        return None;
    }
    let [
        (items_name, Type::List(element, capacity)),
        (next_name, Type::Option(next)),
    ] = fields.as_ref()
    else {
        return None;
    };
    let Type::Tuple(pair) = element.as_ref() else {
        return None;
    };
    let [key, value] = pair.as_slice() else {
        return None;
    };
    let Type::StateCursor(cursor_key) = next.as_ref() else {
        return None;
    };
    (items_name == "items" && next_name == "next" && key == cursor_key.as_ref())
        .then_some((key, value, *capacity))
}
fn static_integer_constant(
    context: &SemanticContext,
    expression: &Expr,
) -> Result<TypedExpr, SemanticError> {
    let typed = analyze_const_expr(
        context,
        expression,
        &context.consts.borrow(),
        Some(&Type::Int),
    )
    .map_err(|_| SemanticError {
        code: "E_UNBOUNDED_ITERATION",
        message: "bound must be a compile-time int constant expression".into(),
    })?;
    let folded = fold_constant_numeric(&typed)?;
    if !matches!(folded.kind(), ExprKind::IntLiteral(_)) {
        return Err(SemanticError {
            code: "E_UNBOUNDED_ITERATION",
            message: "bound must be a compile-time int constant expression".into(),
        });
    }
    Ok(folded)
}
fn static_collection_bound(
    context: &SemanticContext,
    expression: &Expr,
) -> Result<u8, SemanticError> {
    let folded = static_integer_constant(context, expression)?;
    let ExprKind::IntLiteral(value) = folded.kind() else {
        return Err(SemanticError {
            code: "E_UNBOUNDED_ITERATION",
            message: "collection limit must be an int constant expression".into(),
        });
    };
    value
        .try_to_u64()
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| (1..=64).contains(value))
        .ok_or_else(|| SemanticError {
            code: "E_ITERATION_LIMIT",
            message: "collection limit must be in 1..=64".into(),
        })
}
fn analyze_state_page_call(
    context: &SemanticContext,
    name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    vars: &mut HashMap<String, Type>,
) -> Option<Result<TypedExpr, SemanticError>> {
    if !implicit_receiver || args.is_empty() || !matches!(name, "page" | "take") {
        return None;
    }
    let receiver = match analyze_expr(context, &args[0], vars) {
        Ok(value) => value,
        Err(error) => return Some(Err(error)),
    };
    let Type::StateMap(key, value) = resolve_struct_type(&receiver.ty) else {
        return None;
    };
    Some((|| {
        if !typed_map_expr_is_state(context, &receiver) {
            return Err(SemanticError {
                code: "E_STATE_MAP_ALIAS",
                message: "pagination requires a directly declared durable StateMap".into(),
            });
        }
        let names = if name == "page" {
            vec!["after".into(), "limit".into()]
        } else {
            vec!["limit".into()]
        };
        let plan = reorder_flexible_call_arguments(
            name,
            args,
            argument_names,
            true,
            &names,
            &vec![true; names.len()],
        )?;
        let bound =
            static_collection_bound(context, &plan.ordered[if name == "page" { 2 } else { 1 }])?;
        let page_ty = state_page_type(*key.clone(), *value, bound)?;
        let cursor_ty = Type::Option(Box::new(Type::StateCursor(key)));
        let mut after = if name == "page" {
            analyze_expr_expected(context, &plan.ordered[1], vars, Some(&cursor_ty))?
        } else {
            TypedExpr {
                expr: ExprKind::OptionNone,
                ty: cursor_ty.clone(),
            }
        };
        ensure_assignable_and_coerce(&cursor_ty, &mut after)?;
        let limit = TypedExpr {
            expr: ExprKind::IntLiteral(BigInt::from(u32::from(bound))),
            ty: Type::Int,
        };
        if name == "page" {
            Ok(retain_named_call_evaluation_order(
                TypedExpr {
                    expr: ExprKind::Call {
                        target: CallTarget::Intrinsic(CompilerIntrinsic::StatePage),
                        args: vec![receiver, after, limit],
                    },
                    ty: page_ty,
                },
                &plan,
            ))
        } else {
            let Type::Struct { fields, .. } = page_ty else {
                unreachable!("page is a product")
            };
            Ok(TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Intrinsic(CompilerIntrinsic::StateTake),
                    args: vec![receiver, after, limit],
                },
                ty: fields[0].1.clone(),
            })
        }
    })())
}
fn query_page_type(view: Type) -> Result<Type, SemanticError> {
    let Type::Struct {
        name: view_name, ..
    } = &view
    else {
        return Err(SemanticError {
            code: "K2003",
            message: "QueryPage<T> requires one of the five declared core query view types".into(),
        });
    };
    if !matches!(
        view_name.as_str(),
        "kotodama::AccountView"
            | "kotodama::AssetView"
            | "kotodama::AssetDefinitionView"
            | "kotodama::DomainView"
            | "kotodama::NftView"
    ) {
        return Err(SemanticError {
            code: "E_QUERY_PAGE_VIEW",
            message: format!(
                "QueryPage<{view_name}> is unsupported; pages are available only for declared core query views"
            ),
        });
    }
    Ok(Type::Struct {
        // The projection specialization is encoded by the recursive List
        // child. Keeping the nominal name canonical avoids smuggling generic
        // syntax into an ABI identifier while preserving exact schema identity.
        name: QUERY_PAGE_NOMINAL_NAME.to_owned(),
        fields: Arc::from(vec![
            ("items".to_owned(), Type::List(Box::new(view), 64)),
            ("next_offset".to_owned(), Type::Option(Box::new(Type::Int))),
        ]),
    })
}
fn query_page_view_type(ty: &Type) -> Option<&Type> {
    let Type::Struct { name, fields } = ty else {
        return None;
    };
    let [
        (items_name, Type::List(view, capacity)),
        (next_name, Type::Option(next_offset)),
    ] = fields.as_ref()
    else {
        return None;
    };
    (name == QUERY_PAGE_NOMINAL_NAME
        && items_name == "items"
        && *capacity == 64
        && next_name == "next_offset"
        && next_offset.as_ref() == &Type::Int)
        .then_some(view.as_ref())
}
fn core_query_page_type(builtin: Builtin) -> Type {
    query_page_type(
        core_query_view_type(builtin)
            .expect("only projected plural core-query builtins request QueryPage types"),
    )
    .expect("projected plural core-query builtins use supported view types")
}
fn canonicalize_builtin_result<T>(
    builtin: Builtin,
    result: Result<T, SemanticError>,
) -> Result<T, SemanticError> {
    result.map_err(|mut error| {
        if builtin.name() != builtin.source_name() {
            error.message =
                replace_identifier_token(&error.message, builtin.name(), builtin.source_name());
        }
        error
    })
}
fn replace_identifier_token(message: &str, needle: &str, replacement: &str) -> String {
    fn is_identifier_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':')
    }
    let mut rewritten = String::with_capacity(message.len() + replacement.len());
    let mut copied_until = 0;
    for (start, _) in message.match_indices(needle) {
        let end = start + needle.len();
        let has_identifier_prefix = message[..start]
            .bytes()
            .next_back()
            .is_some_and(is_identifier_byte);
        let has_identifier_suffix = message[end..]
            .bytes()
            .next()
            .is_some_and(is_identifier_byte);
        if has_identifier_prefix || has_identifier_suffix {
            continue;
        }
        rewritten.push_str(&message[copied_until..start]);
        rewritten.push_str(replacement);
        copied_until = end;
    }
    rewritten.push_str(&message[copied_until..]);
    rewritten
}
fn coerce_builtin_exact_numeric_literals(
    builtin: Builtin,
    arguments: &mut [TypedExpr],
) -> Result<(), SemanticError> {
    for (argument, parameter) in arguments
        .iter_mut()
        .zip(builtin.signature().parameters.iter().copied())
    {
        let expected = match parameter.strip_suffix('?').unwrap_or(parameter) {
            "decimal" => Type::Decimal,
            "quantity" => Type::Quantity,
            _ => continue,
        };
        coerce_exact_numeric_literal_to(argument, &expected)?;
    }
    Ok(())
}
fn typed_expr(expr: ExprKind, ty: Type) -> TypedExpr {
    TypedExpr { expr, ty }
}

fn typed_builtin_call(builtin: Builtin, args: Vec<TypedExpr>, ty: Type) -> TypedExpr {
    typed_expr(
        ExprKind::Call {
            target: CallTarget::Builtin(builtin),
            args,
        },
        ty,
    )
}

#[derive(Clone, Copy)]
enum FixedBuiltinMessage {
    Static(&'static str),
    NameSuffix(&'static str),
    SourceNameSuffix(&'static str),
}

impl FixedBuiltinMessage {
    fn render(self, builtin: Builtin) -> String {
        match self {
            Self::Static(message) => message.to_owned(),
            Self::NameSuffix(suffix) => format!("{}{suffix}", builtin.name()),
            Self::SourceNameSuffix(suffix) => format!("{}{suffix}", builtin.source_name()),
        }
    }
}

fn fixed_builtin_message(builtin: Builtin) -> Option<FixedBuiltinMessage> {
    use FixedBuiltinMessage as M;

    Some(match builtin {
        Builtin::StateGet => M::Static("state_get expects (bytes StatePath)"),
        Builtin::StateSet => M::Static("state_set expects (bytes StatePath, bytes value)"),
        Builtin::StateDel => M::Static("state_del expects (bytes StatePath)"),
        Builtin::StateHas => M::Static("state_has expects (bytes StatePath)"),
        Builtin::StateLen => M::Static("state_len expects (bytes StatePath)"),
        Builtin::StateCount => M::Static("state_count expects (bytes StatePath)"),
        Builtin::QueryExecuteNorito => {
            M::Static("query_execute_norito expects (bytes) pointer to NoritoBytes QueryRequest")
        }
        Builtin::QueryGetParameter => M::Static("query_get_parameter expects (Name|bytes)"),
        Builtin::QueryGetContractManifest => {
            M::Static("query_get_contract_manifest expects (bytes) Norito Hash")
        }
        Builtin::QueryGetContractInstance => {
            M::Static("query_get_contract_instance expects (Name|bytes)")
        }
        Builtin::ZkRootsGet => {
            M::Static("zk_roots_get expects (bytes) pointer to NoritoBytes RootsGetRequest")
        }
        Builtin::ZkVoteGetTally => M::Static(
            "zk_vote_get_tally expects (bytes) pointer to NoritoBytes VoteGetTallyRequest",
        ),
        Builtin::VrfEpochSeed => {
            M::Static("crypto::vrf::epoch_seed expects (int epoch) and returns Option<bytes>")
        }
        Builtin::BuildSubmitBallotInline => M::Static(
            "build_submit_ballot_inline expects (string election_id, bytes ciphertext, bytes nullifier32, string backend, bytes proof, bytes vk)",
        ),
        Builtin::ScExecuteSubmitBallot
        | Builtin::ZkVerifyBatch
        | Builtin::ZkVoteVerifyBallot
        | Builtin::ZkVoteVerifyTally => M::NameSuffix(
            " expects (bytes) where the argument is a pointer to NoritoBytes TLV in INPUT",
        ),
        Builtin::ExecuteQuery => M::NameSuffix(
            " expects (bytes) where the argument is a pointer to NoritoBytes TLV in INPUT",
        ),
        Builtin::ResolveAccountAlias => M::Static("resolve_account_alias expects (string|bytes)"),
        Builtin::SubscriptionBill | Builtin::SubscriptionRecordUsage => {
            M::NameSuffix(" expects no arguments")
        }
        Builtin::VrfVerify => M::Static("vrf_verify expects one bytes-encoded VrfVerifyRequest"),
        Builtin::VrfVerifyBatch => M::Static("vrf_verify_batch expects (bytes)"),
        Builtin::Sm3Hash
        | Builtin::Sha256Hash
        | Builtin::Sha3Hash
        | Builtin::Blake2b256Hash
        | Builtin::Keccak256Hash
        | Builtin::IrohaHash => M::NameSuffix(" expects (bytes) argument pointing to INPUT TLV"),
        Builtin::Sm4GcmSeal | Builtin::Sm4GcmOpen => {
            M::NameSuffix(" expects (bytes, bytes, bytes, bytes)")
        }
        Builtin::VerifySignature => M::SourceNameSuffix(
            " expects (message: bytes, signature: bytes, public_key: bytes, scheme: SignatureScheme)",
        ),
        Builtin::GetAccountBalance => {
            M::Static("get_account_balance expects (AccountId, AssetDefinitionId)")
        }
        Builtin::GetPublicInput => M::Static("get_public_input expects (Name)"),
        Builtin::DebugPrint => M::Static("debug_print expects (int value)"),
        Builtin::DebugLog => M::Static("debug_log expects (Json|bytes payload)"),
        Builtin::Require => M::Static("require expects (bool, ErrorEnum::Variant)"),
        Builtin::Info => M::Static("info expects (string|int)"),
        Builtin::AssertEq => {
            M::Static("assert_eq expects (actual: T, expected: T[, message: string|int])")
        }
        Builtin::SetAccountMetadata => {
            M::Static("set_account_metadata expects (AccountId, Name, Json)")
        }
        Builtin::MintAsset | Builtin::BurnAsset => {
            M::NameSuffix(" expects (AccountId, AssetDefinitionId, quantity)")
        }
        Builtin::TransferAsset => M::Static(
            "transfer_asset expects (AccountId, AccountId, AssetDefinitionId, quantity[, DataSpaceId])",
        ),
        Builtin::SetAssetTransferAvailability => M::Static(
            "ledger::asset::set_transfer_availability expects (AccountId, AssetDefinitionId, int, bool, bool, Option<string>)",
        ),
        Builtin::SetAssetTransferDailyLimit => M::Static(
            "ledger::asset::set_transfer_daily_limit expects (AccountId, AssetDefinitionId, Option<quantity>)",
        ),
        Builtin::SetAssetHoldingLimit => M::Static(
            "ledger::asset::set_holding_limit expects (AccountId, AssetDefinitionId, Option<quantity>)",
        ),
        Builtin::AccountRecoveryPropose => {
            M::Static("ledger::account::recovery::propose expects (string, AccountId, int)")
        }
        Builtin::AccountRecoveryApprove
        | Builtin::AccountRecoveryCancel
        | Builtin::AccountRecoveryFinalize => M::SourceNameSuffix(" expects (string, int)"),
        Builtin::NftMintAsset => M::Static("nft_mint_asset expects (NftId, AccountId)"),
        Builtin::NftSetMetadata => M::Static("nft_set_metadata expects (NftId, Name, Json)"),
        Builtin::NftBurnAsset => M::Static("nft_burn_asset expects (NftId)"),
        Builtin::NftTransferAsset => {
            M::Static("nft_transfer_asset expects (AccountId, NftId, AccountId)")
        }
        Builtin::RegisterDomain | Builtin::UnregisterDomain => M::NameSuffix(" expects (DomainId)"),
        Builtin::TransferDomain => {
            M::Static("transfer_domain expects (AccountId, DomainId, AccountId)")
        }
        Builtin::RegisterAccount | Builtin::UnregisterAccount => {
            M::NameSuffix(" expects (AccountId)")
        }
        Builtin::UnregisterAsset => M::Static("unregister_asset expects (AssetDefinitionId)"),
        Builtin::RegisterPeer | Builtin::UnregisterPeer | Builtin::RegisterTrigger => {
            M::NameSuffix(" expects (Json)")
        }
        Builtin::UnregisterTrigger
        | Builtin::EscrowAccept
        | Builtin::EscrowMarkPaymentSent
        | Builtin::EscrowRelease
        | Builtin::EscrowCancel => M::NameSuffix(" expects (Name)"),
        Builtin::SetTriggerEnabled => M::Static("set_trigger_enabled expects (Name, bool)"),
        Builtin::RegisterRole => M::Static("register_role expects (Name, Json)"),
        Builtin::UnregisterRole => M::Static("unregister_role expects (Name)"),
        Builtin::GrantRole | Builtin::RevokeRole => M::NameSuffix(" expects (AccountId, Name)"),
        Builtin::GrantPermission | Builtin::RevokePermission => {
            M::NameSuffix(" expects (AccountId, Name|Json)")
        }
        Builtin::Alloc => M::Static("alloc expects (int bytes)"),
        Builtin::ExecutionSummary => M::Static("execution_summary expects no arguments"),
        Builtin::GrowHeap => M::Static("grow_heap expects (int bytes)"),
        Builtin::VerifyProof => {
            M::Static("verify_proof expects (bytes) pointer to NoritoBytes OpenVerifyEnvelope")
        }
        Builtin::CommitOutput => M::Static("commit_output expects no arguments"),
        Builtin::CreateNftsForAllUsers => {
            M::Static("create_nfts_for_all_users expects no arguments")
        }
        Builtin::SetExecutionDepth => M::Static("set_execution_depth expects one int arg"),
        Builtin::AxtBegin => M::Static("axt_begin expects (AxtDescriptor)"),
        Builtin::StageAnchoredSpend => {
            M::Static("axt_stage_anchored_spend expects (AxtAnchoredSpendV1)")
        }
        Builtin::AxtCommit => M::Static("axt_commit expects no arguments"),
        Builtin::DeactivateContractInstance
        | Builtin::RemoveSmartContractBytes
        | Builtin::RegisterSmartContractCode
        | Builtin::RegisterSmartContractBytes
        | Builtin::ActivateContractInstance => {
            M::NameSuffix(" expects (bytes) pointer to NoritoBytes lifecycle request")
        }
        Builtin::SoracloudReadCommittedState
        | Builtin::SoracloudEmitStateMutation
        | Builtin::SoracloudEmitMailboxMessage
        | Builtin::SoracloudAppendJournal
        | Builtin::SoracloudPublishCheckpoint
        | Builtin::SoracloudReadConfig
        | Builtin::SoracloudReadSecretEnvelope => M::NameSuffix(" expects (SoracloudRequest)"),
        Builtin::AddSignatory | Builtin::RemoveSignatory => {
            M::NameSuffix(" expects (AccountId, Json)")
        }
        Builtin::Path => {
            M::Static("path expects a Name and a canonical scalar or tuple StateMap key")
        }
        Builtin::NameDecode => M::Static("name_decode expects (bytes)"),
        Builtin::TlvEq => M::Static("tlv_eq expects (pointer-ABI, pointer-ABI)"),
        Builtin::BytesLen => M::Static("bytes::len expects exactly one bytes argument"),
        Builtin::BytesConcat => M::Static("bytes::concat expects (bytes left, bytes right)"),
        Builtin::StringConcat => M::Static("string::concat expects (string left, string right)"),
        Builtin::StringLen => M::Static("string::len expects (string)"),
        Builtin::StringAsBytes => M::Static("string::as_bytes expects (string)"),
        Builtin::StringFromBytes => M::Static("string::from_bytes expects (bytes)"),
        Builtin::JsonObject => M::Static("json_object expects no arguments"),
        Builtin::JsonSetInt => M::Static("json_set_int expects (Json, Name, int)"),
        Builtin::JsonSetAccountId => {
            M::Static("json_set_account_id expects (Json, Name, AccountId)")
        }
        Builtin::EncodeJson => M::Static("encode_json expects (Json)"),
        Builtin::DecodeJson => M::Static("decode_json expects (bytes)"),
        Builtin::SchemaEncode => M::Static("encode_schema expects (Name, Json)"),
        Builtin::SchemaDecode => M::Static("decode_schema expects (Name, bytes)"),
        Builtin::SchemaInfo => M::Static("schema_info expects (Name)"),
        Builtin::NumericToInt => M::Static("numeric_to_int expects (quantity|int)"),
        Builtin::NumericToIntDirect => {
            M::Static("numeric_to_int_direct expects (int); quantity uses its nominal V1 syscall")
        }
        Builtin::WrappingNeg => M::Static("wrapping_neg expects (int)"),
        Builtin::WrappingAdd | Builtin::WrappingSub | Builtin::WrappingMul => {
            M::NameSuffix(" expects (int, int)")
        }
        Builtin::Isqrt => M::NameSuffix(" expects (int)"),
        Builtin::DivCeil | Builtin::Gcd | Builtin::Mean => M::NameSuffix(" expects (int, int)"),
        Builtin::Poseidon2 => M::SourceNameSuffix(" expects two int arguments"),
        Builtin::Valcom => {
            M::SourceNameSuffix(" expects two typed Secret<int|decimal|quantity> arguments")
        }
        Builtin::Poseidon6 => M::SourceNameSuffix(" expects six int args"),
        Builtin::Pubkgen => M::SourceNameSuffix(" expects one int arg"),
        Builtin::SetVl => M::Static("setvl expects one int arg"),
        Builtin::GetInt => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetDecimal => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetQuantity => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetJson => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetName => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetAccountId => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetAssetDefinitionId => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetNftId => M::NameSuffix(" expects (Json, Name)"),
        Builtin::GetBytesHex | Builtin::GetString | Builtin::GetBool => {
            M::NameSuffix(" expects (Json, Name)")
        }
        Builtin::Authority | Builtin::SysvarAuthority | Builtin::ContractSubject => {
            M::NameSuffix(" expects no arguments")
        }
        Builtin::TransactionTimeMs | Builtin::BlockHeight | Builtin::BlockTimeMs => {
            M::NameSuffix(" expects no arguments")
        }
        Builtin::ChainId | Builtin::ContractAddress | Builtin::Entrypoint => {
            M::NameSuffix(" expects no arguments")
        }
        _ => return None,
    })
}

fn fixed_builtin_arg_accepts(builtin: Builtin, index: usize, descriptor: &str, ty: &Type) -> bool {
    match (builtin, index) {
        (Builtin::DebugLog, 0) => ty == &Type::Json || is_blob_like(ty),
        (Builtin::SetAssetTransferAvailability, 2) => ty == &Type::Int,
        (Builtin::NumericToIntDirect, 0) => resolve_struct_type(ty) == Type::Int,
        (Builtin::TlvEq, _) => {
            let ty = resolve_struct_type(ty);
            is_pointer_type(&ty) || is_blob_like(&ty) || ty == Type::Json
        }
        _ => match descriptor.strip_suffix('?').unwrap_or(descriptor) {
            "AccountId" => ty == &Type::AccountId,
            "AssetDefinitionId" => ty == &Type::AssetDefinitionId,
            "AxtDescriptor" => ty == &Type::AxtDescriptor,
            "AxtAnchoredSpendV1" => ty == &Type::AxtAnchoredSpendV1,
            "DataSpaceId" => ty == &Type::DataSpaceId,
            "DomainId" => ty == &Type::DomainId,
            "DomainId|Name" => matches!(ty, Type::DomainId | Type::Name),
            "ErrorEnum::Variant" => matches!(resolve_struct_type(ty), Type::ErrorEnum(_)),
            "Json" => ty == &Type::Json,
            "Name" => ty == &Type::Name,
            "Name|Json" => matches!(ty, Type::Name | Type::Json),
            "Name|bytes" => ty == &Type::Name || is_blob_like(ty),
            "NftId" => ty == &Type::NftId,
            "Option<quantity>" => resolve_struct_type(ty) == Type::Option(Box::new(Type::Quantity)),
            "Option<string>" => resolve_struct_type(ty) == Type::Option(Box::new(Type::String)),
            "Secret<int|decimal|quantity>" => crate::secret::is_secret_numeric(ty),
            "SoracloudRequest" => resolve_struct_type(ty) == Type::SoracloudRequest,
            // Folded by `nominal_argument_word` into the host register word.
            "NumericSpec" | "Mintable" | "SignatureScheme" => ty == &Type::Int,
            "bool" => ty == &Type::Bool,
            "bytes" => is_blob_like(ty),
            "int" => is_int_like(ty),
            "K" => is_supported_durable_key_type(ty),
            "pointer-ABI" => {
                let ty = resolve_struct_type(ty);
                is_pointer_type(&ty) || is_blob_like(&ty) || ty == Type::Json
            }
            "quantity" => ty == &Type::Quantity,
            "string" => ty == &Type::String,
            "string|bytes" => ty == &Type::String || is_blob_like(ty),
            "string|int" => ty == &Type::String || is_int_like(ty),
            "wide-numeric" => is_wide_numeric_type(ty),
            _ => unreachable!("fixed builtin has unsupported argument descriptor `{descriptor}`"),
        },
    }
}

fn fixed_builtin_result_type(descriptor: &str) -> Type {
    let option = |payload| Type::Option(Box::new(payload));
    match descriptor {
        "()" => Type::Unit,
        "AccountId" => Type::AccountId,
        "Json" => Type::Json,
        "Name" => Type::Name,
        "Option<AccountId>" => option(Type::AccountId),
        "Option<AssetDefinitionId>" => option(Type::AssetDefinitionId),
        "Option<Json>" => option(Type::Json),
        "Option<Name>" => option(Type::Name),
        "Option<NftId>" => option(Type::NftId),
        "Option<bytes>" => option(Type::Bytes),
        "Option<bool>" => option(Type::Bool),
        "Option<string>" => option(Type::String),
        "Option<decimal>" => option(Type::Decimal),
        "Option<int>" => option(Type::Int),
        "Option<quantity>" => option(Type::Quantity),
        "string" => Type::String,
        "SoracloudResponse" => Type::SoracloudResponse,
        "bool" => Type::Bool,
        "bytes" => Type::Bytes,
        "int" => Type::Int,
        "quantity" => Type::Quantity,
        _ => unreachable!("fixed builtin has unsupported result descriptor `{descriptor}`"),
    }
}

fn analyze_fixed_builtin_call(
    builtin: Builtin,
    args: Vec<TypedExpr>,
) -> Result<TypedExpr, SemanticError> {
    let message = fixed_builtin_message(builtin).expect("remaining builtin has a fixed signature");
    let signature = builtin.signature();
    // Optional parameters are trailing (`T?`); omitted ones are simply absent.
    let required = signature
        .parameters
        .iter()
        .filter(|parameter| !parameter.ends_with('?'))
        .count();
    if args.len() < required
        || args.len() > signature.parameters.len()
        || args
            .iter()
            .enumerate()
            .zip(signature.parameters.iter().copied())
            .any(|((index, argument), descriptor)| {
                !fixed_builtin_arg_accepts(builtin, index, descriptor, &argument.ty)
            })
    {
        return Err(sem_err("K2003", message.render(builtin)));
    }
    let expression = typed_builtin_call(
        builtin,
        args,
        fixed_builtin_result_type(signature.return_type),
    );
    if matches!(
        builtin,
        Builtin::Isqrt | Builtin::DivCeil | Builtin::Gcd | Builtin::Mean
    ) {
        match crate::checked_arithmetic::evaluate(&expression) {
            Ok(Some(value)) => Ok(value.into_typed_expr()),
            Ok(None) => Ok(expression),
            Err(error) => Err(SemanticError {
                code: error.code(),
                message: error.to_string(),
            }),
        }
    } else {
        Ok(expression)
    }
}

/// Every receiver method of a durable `StateMap`, as the spec's Durable state
/// section lists them.
const STATE_MAP_METHODS: &[&str] = &["get", "contains", "get_or_insert", "remove", "page", "take"];

/// Help for a call of a method `StateMap` does not have.
///
/// Defaulting reads point at the explicit `Option` idiom rather than at the
/// closest spelling, because the closest helper (`get_or_insert`) writes state.
fn unknown_state_map_method_help(method: &str) -> String {
    let surface = "`StateMap` methods are `get`, `contains`, `get_or_insert`, `remove`, `page`, and `take`; write with `map[key] = value`.";
    match method {
        "get_or" | "get_or_default" | "get_or_else" | "unwrap_or" => format!(
            "`map.get(key)` returns `Option<V>`; handle absence explicitly with `map.get(key).unwrap_or(default)`, `map.get(key).expect(Error::Missing)`, or a `match` when the fallback must only be evaluated on absence. A missing key is never read as zero. {surface}"
        ),
        "ensure" | "insert" | "insert_default" | "entry" | "or_insert" => format!(
            "`map.get_or_insert(key, default)` writes `default` when the key is absent and returns the stored value; `map[key] = value` writes unconditionally. {surface}"
        ),
        _ => match crate::diagnostic::suggest::closest(method, STATE_MAP_METHODS.iter().copied()) {
            Some(candidate) => format!("did you mean `{candidate}`? {surface}"),
            None => surface.to_owned(),
        },
    }
}

fn analyze_map_get_or_insert(
    context: &SemanticContext,
    builtin: Builtin,
    mut args: Vec<TypedExpr>,
) -> Result<TypedExpr, SemanticError> {
    let name = builtin.name();
    if args.len() != 3 {
        return Err(sem_err(
            "K2003",
            format!("{name} expects (StateMap<K,V>, K, V); absence never defaults implicitly"),
        ));
    }
    let (key, value) = match resolve_struct_type(&args[0].ty) {
        Type::StateMap(key, value) => (*key, *value),
        other => {
            return Err(sem_err(
                "K2003",
                format!(
                    "{name} expects StateMap<K,V> as first arg, got {}",
                    type_name(&other)
                ),
            ));
        }
    };
    let key = resolve_struct_type(&key);
    let value = resolve_struct_type(&value);
    ensure_assignable_and_coerce(&key, &mut args[1])?;
    ensure_in_memory_map_word_types(context, &args[0])?;
    ensure_assignable_and_coerce(&value, &mut args[2])?;
    Ok(typed_builtin_call(builtin, args, value))
}

/// Grant operations accept only a compile-time instance permission declaration.
fn analyze_permission_grant_call(
    _context: &SemanticContext,
    builtin: Builtin,
    args: Vec<TypedExpr>,
) -> Result<TypedExpr, SemanticError> {
    if args.len() != 2 || args[0].ty != Type::AccountId || args[1].ty != Type::Name {
        return Err(sem_err(
            "K2003",
            format!(
                "{} expects (account: AccountId, permission: DeclaredPermission)",
                builtin.source_name()
            ),
        ));
    }
    Ok(typed_builtin_call(builtin, args, Type::Unit))
}

/// Check `ledger::asset::register` after its `spec:` and `mintable:` arguments
/// were folded into register words by [`nominal_argument_word`].
fn analyze_register_asset_call(
    builtin: Builtin,
    args: Vec<TypedExpr>,
) -> Result<TypedExpr, SemanticError> {
    if args.len() != 4
        || args[0].ty != Type::AssetDefinitionId
        || resolve_struct_type(&args[1].ty) != Type::String
        || !matches!(args[2].kind(), ExprKind::IntLiteral(_))
        || !matches!(args[3].kind(), ExprKind::IntLiteral(_))
    {
        return Err(sem_err(
            "K2003",
            "ledger::asset::register expects (asset_definition: AssetDefinitionId, name: string, spec: NumericSpec::..., mintable: Mintable::...)".into(),
        ));
    }
    if let ExprKind::String(name) = args[1].kind()
        && let Err(error) = iroha_data_model::asset::definition::validate_asset_name(name)
    {
        return Err(sem_err(
            "E_ASSET_NAME_INVALID",
            format!("invalid `name:` display name for ledger::asset::register: {error}"),
        ));
    }
    Ok(typed_builtin_call(builtin, args, Type::Unit))
}

/// Analyze builtin arguments whose meaning is fixed at compile time.
///
/// `NumericSpec`, `Mintable` and `SignatureScheme` parameters fold their
/// compile-time nominal value into the register word the host decodes, and a
/// string-literal JSON getter key becomes the same compile-time-validated
/// `Name` as `Name::parse("...")`. Every other argument returns `None` and is
/// analyzed as an ordinary expression.
fn analyze_builtin_literal_argument(
    context: &SemanticContext,
    builtin: Builtin,
    index: usize,
    argument: &Expr,
) -> Result<Option<TypedExpr>, SemanticError> {
    if matches!(
        builtin,
        Builtin::GrantContractPermission | Builtin::RevokeContractPermission
    ) && index == 1
    {
        let Expr::Ident(name) = argument.kind() else {
            return Err(sem_err(
                "E_PERMISSION_ARGUMENT",
                "permission grants require a declared instance permission identifier".into(),
            ));
        };
        match context.permissions.borrow().get(name) {
            Some(ContractPermissionScopeV1::Instance) => {}
            Some(ContractPermissionScopeV1::Chain { .. }) => {
                return Err(sem_err(
                    "E_PERMISSION_ARGUMENT",
                    format!(
                        "`{name}` is an imported chain permission; seiyaku grant operations only manage instance permissions"
                    ),
                ));
            }
            None => {
                return Err(sem_err(
                    "E_UNKNOWN_PERMISSION",
                    format!("undeclared instance permission `{name}`"),
                ));
            }
        }
        return Ok(Some(TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Builtin(Builtin::PointerConstructor(PointerConstructor::Name)),
                args: vec![typed_expr(ExprKind::String(name.clone()), Type::String)],
            },
            ty: Type::Name,
        }));
    }
    let Some(descriptor) = builtin.signature().parameters.get(index).copied() else {
        return Ok(None);
    };
    if matches!(descriptor, "NumericSpec" | "Mintable" | "SignatureScheme") {
        return nominal_argument_word(context, builtin, index, descriptor, argument)
            .map(Some)
            .inspect_err(|_| {
                // Point at the argument and list only the forms its type accepts.
                context.capture_help(
                    context.expression_source(argument),
                    nominal_argument_help(descriptor),
                );
            });
    }
    if builtin == Builtin::RegisterAsset
        && index == 1
        && let Expr::String(raw) = argument.kind()
        && let Err(error) = iroha_data_model::asset::definition::validate_asset_name(raw)
    {
        // Point at the literal; the host would reject the same name at runtime.
        context.capture_help(
            context.expression_source(argument),
            "An asset display name is non-blank, at most 128 characters, and contains no `#`, `@`, or control characters.".to_owned(),
        );
        return Err(sem_err(
            "E_ASSET_NAME_INVALID",
            format!("invalid `name:` display name for ledger::asset::register: {error}"),
        ));
    }
    if builtin.is_payload_helper()
        && builtin.surface() == BuiltinSurface::MethodOnly
        && descriptor == "Name"
        && let Expr::String(raw) = argument.kind()
    {
        if let Err(invalid) = id_literals::validate(
            PointerConstructor::Name,
            raw,
            iroha_data_model::account::address::chain_discriminant(),
        ) {
            context.capture_help(
                context.expression_source(argument),
                format!(
                    "A typed JSON getter key is a `Name`. {} Fields whose keys are not `Name`s cannot be read with typed getters.",
                    invalid.help
                ),
            );
            return Err(sem_err(
                "E_INVALID_ID_LITERAL",
                format!("JSON key {}", invalid.message),
            ));
        }
        return Ok(Some(TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Builtin(Builtin::PointerConstructor(PointerConstructor::Name)),
                args: vec![typed_expr(ExprKind::String(raw.clone()), Type::String)],
            },
            ty: Type::Name,
        }));
    }
    Ok(None)
}

/// Reject a compile-time nominal value used anywhere but as the argument of
/// the builtin parameter of its type.
fn misplaced_nominal_value(builtin: Builtin) -> SemanticError {
    let descriptor = builtin.signature().return_type;
    let target = Builtin::all()
        .filter(|candidate| candidate.surface() != BuiltinSurface::CompilerInternal)
        .find_map(|candidate| {
            let signature = candidate.signature();
            signature
                .parameters
                .iter()
                .position(|parameter| *parameter == descriptor)
                .map(|index| {
                    format!(
                        "the `{}:` argument of `{}`",
                        signature.parameter_names[index],
                        candidate.source_name()
                    )
                })
        })
        .unwrap_or_else(|| "its builtin argument".to_owned());
    SemanticError {
        code: "E_NOMINAL_ARGUMENT",
        message: format!(
            "`{}` is a compile-time `{descriptor}` value; write it directly as {target}",
            builtin.source_name()
        ),
    }
}

/// Site-specific help for an argument of the compile-time nominal type
/// `descriptor`, listing only the forms that type accepts.
fn nominal_argument_help(descriptor: &str) -> String {
    format!(
        "Write one `{descriptor}` value directly as this argument: {}. It is folded at compile time, so a local, parameter, or integer cannot stand in for it.",
        nominal_value_forms(descriptor)
    )
}
/// The source forms a compile-time nominal parameter accepts, for diagnostics.
fn nominal_value_forms(descriptor: &str) -> String {
    Builtin::all()
        .filter(|builtin| {
            builtin.is_compile_time_nominal() && builtin.signature().return_type == descriptor
        })
        .map(|builtin| {
            let path = builtin.source_name();
            let call = |arguments: &str| format!("`{path}({arguments})`");
            if builtin.is_nominal_path() {
                format!("`{path}`")
            } else {
                call(&builtin.signature().parameter_names.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Fold a compile-time `NumericSpec`, `Mintable` or `SignatureScheme` argument
/// into the register word shared with every contract host.
///
/// `Mintable` and `SignatureScheme` are compiler-owned nominal enums: a
/// payloadless variant is a path (`Mintable::Once`), the payload variant a call
/// (`Mintable::Limited(3)`). `NumericSpec` values are constructor calls
/// (`NumericSpec::integer()`). Integers and runtime values are rejected, so an
/// unknown mintability, numeric spec or signature scheme cannot be expressed.
fn nominal_argument_word(
    context: &SemanticContext,
    target: Builtin,
    index: usize,
    descriptor: &str,
    expression: &Expr,
) -> Result<TypedExpr, SemanticError> {
    use iroha_data_model::asset::definition::{Mintable, ivm_registration};
    use iroha_primitives::numeric::NumericSpec;
    let label = target
        .signature()
        .parameter_names
        .get(index)
        .copied()
        .unwrap_or("argument");
    let expected = |found: &str| SemanticError {
        code: "E_NOMINAL_ARGUMENT",
        message: format!(
            "`{label}:` of `{}` takes a `{descriptor}` value written directly at the call ({}){found}",
            target.source_name(),
            nominal_value_forms(descriptor)
        ),
    };
    let (path, args) = match expression.kind() {
        Expr::Ident(path) => (path.as_str(), None),
        Expr::Call {
            name,
            args,
            implicit_receiver: false,
            ..
        } => (name.as_str(), Some(args)),
        _ => return Err(expected("")),
    };
    let Some(builtin) = Builtin::nominal_value(path)
        .filter(|builtin| builtin.signature().return_type == descriptor)
    else {
        let found = Builtin::all()
            .filter(|builtin| {
                builtin.is_compile_time_nominal() && builtin.signature().return_type == descriptor
            })
            .find(|builtin| builtin.source_name().eq_ignore_ascii_case(path))
            .map(|builtin| format!("; did you mean `{}`?", builtin.source_name()))
            .unwrap_or_default();
        return Err(expected(&found));
    };
    let args: &[Expr] = match (builtin.is_nominal_path(), args) {
        (true, None) => &[],
        (false, Some(args)) => args,
        (true, Some(_)) => {
            return Err(SemanticError {
                code: "E_NOMINAL_ARGUMENT",
                message: format!(
                    "`{path}` is a value, not a call; write `{path}` without parentheses"
                ),
            });
        }
        (false, None) => {
            return Err(SemanticError {
                code: "E_NOMINAL_ARGUMENT",
                message: format!("`{path}` is a call; write `{path}(...)`"),
            });
        }
    };
    let arity = builtin.signature().parameters.len();
    if args.len() != arity {
        return Err(SemanticError {
            code: "E_NOMINAL_ARGUMENT",
            message: format!(
                "`{}` expects {arity} argument{}",
                builtin.source_name(),
                if arity == 1 { "" } else { "s" }
            ),
        });
    }
    let constant = |range: core::ops::RangeInclusive<u64>| -> Result<u64, SemanticError> {
        let value = static_integer_constant(context, &args[0]).map_err(|error| SemanticError {
            code: "E_NOMINAL_ARGUMENT",
            message: format!(
                "`{}` requires a compile-time integer: {}",
                builtin.source_name(),
                error.message
            ),
        })?;
        literal_int(&value)
            .and_then(|value| value.try_to_u64())
            .filter(|value| range.contains(value))
            .ok_or_else(|| SemanticError {
                code: "E_NOMINAL_ARGUMENT",
                message: format!(
                    "`{}` argument must be in {}..={}",
                    builtin.source_name(),
                    range.start(),
                    range.end()
                ),
            })
    };
    let word = match builtin {
        Builtin::NumericSpecUnconstrained => {
            ivm_registration::numeric_spec_word(NumericSpec::unconstrained())
        }
        Builtin::NumericSpecInteger => ivm_registration::numeric_spec_word(NumericSpec::integer()),
        Builtin::NumericSpecFractional => {
            let scale = constant(0..=u64::from(ivm_registration::MAX_SCALE))?;
            let scale = u32::try_from(scale).expect("scale range fits u32");
            ivm_registration::numeric_spec_word(NumericSpec::fractional(scale))
        }
        Builtin::MintableInfinitely => ivm_registration::mintable_word(Mintable::Infinitely),
        Builtin::MintableOnce => ivm_registration::mintable_word(Mintable::Once),
        Builtin::MintableNot => ivm_registration::mintable_word(Mintable::Not),
        Builtin::MintableLimited => {
            let tokens = constant(1..=u64::from(u32::MAX))?;
            let tokens = u32::try_from(tokens).expect("token range fits u32");
            ivm_registration::mintable_word(
                Mintable::limited_from_u32(tokens).expect("token range excludes zero"),
            )
        }
        Builtin::SignatureSchemeEd25519
        | Builtin::SignatureSchemeSecp256k1
        | Builtin::SignatureSchemeMlDsa => u64::from(
            builtin
                .signature_scheme_code()
                .expect("signature scheme value has a host code"),
        ),
        _ => return Err(expected("")),
    };
    Ok(typed_expr(
        ExprKind::IntLiteral(BigInt::from(word)),
        Type::Int,
    ))
}

fn validate_builtin_mode(context: &SemanticContext, builtin: Builtin) -> Result<(), SemanticError> {
    match builtin.spec().mode {
        BuiltinMode::CompilerInternal => {
            return Err(SemanticError {
                code: "E_INTERNAL_BUILTIN",
                message: format!(
                    "builtin `{}` is compiler-internal and is not available in Kotodama V1 source",
                    builtin.name()
                ),
            });
        }
        BuiltinMode::ZkOnly if !context.zk_enabled => {
            return Err(SemanticError {
                code: "E_ZK_MODE_REQUIRED",
                message: format!(
                    "builtin `{}` requires ZK mode in compiler build configuration",
                    builtin.source_name()
                ),
            });
        }
        BuiltinMode::TestOnly | BuiltinMode::TestFunctionOnly if !context.test_builtins_enabled => {
            return Err(SemanticError {
                code: "E_TEST_ONLY_PRODUCTION",
                message: format!(
                    "builtin `{}` requires explicit compiler test mode",
                    builtin.source_name()
                ),
            });
        }
        BuiltinMode::TestFunctionOnly if !current_function_is_test(context) => {
            return Err(SemanticError {
                code: "E_TEST_BUILTIN_CONTEXT",
                message: format!(
                    "builtin `{}` is available only in #[test] functions and in helpers of a `koto_test` module",
                    builtin.source_name()
                ),
            });
        }
        BuiltinMode::Any
        | BuiltinMode::ZkOnly
        | BuiltinMode::TestOnly
        | BuiltinMode::TestFunctionOnly => {}
    }
    Ok(())
}

fn analyze_surface_builtin_call(
    context: &SemanticContext,
    builtin: Builtin,
    mut arg_typed: Vec<TypedExpr>,
    expected: Option<&Type>,
) -> Result<TypedExpr, SemanticError> {
    validate_builtin_mode(context, builtin)?;
    coerce_builtin_exact_numeric_literals(builtin, &mut arg_typed)?;
    crate::secret::validate_builtin_call(builtin, &arg_typed)?;
    match builtin {
        Builtin::Min | Builtin::Max | Builtin::Abs => {
            let arity = if builtin == Builtin::Abs { 1 } else { 2 };
            let ty = arg_typed
                .first()
                .map(|argument| resolve_struct_type(&argument.ty));
            if arg_typed.len() != arity
                || !ty.as_ref().is_some_and(is_wide_numeric_type)
                || arg_typed
                    .iter()
                    .any(|argument| Some(resolve_struct_type(&argument.ty)) != ty)
            {
                return Err(sem_err(
                    "K2003",
                    format!(
                        "{} expects {arity} operands of one identical int, decimal, or quantity type",
                        builtin.source_name()
                    ),
                ));
            }
            let expression =
                typed_builtin_call(builtin, arg_typed, ty.expect("checked numeric operand"));
            match crate::checked_arithmetic::evaluate(&expression) {
                Ok(Some(value)) => Ok(value.into_typed_expr()),
                Ok(None) => Ok(expression),
                Err(error) => Err(sem_err(error.code(), error.to_string())),
            }
        }
        Builtin::ValueEncode | Builtin::StringFrom => {
            if arg_typed.len() != 1 {
                return Err(sem_err(
                    "K2003",
                    format!("{} expects one value", builtin.source_name()),
                ));
            }
            let ty = resolve_struct_type(&arg_typed[0].ty);
            let supported = if builtin == Builtin::StringFrom {
                matches!(
                    ty,
                    Type::Int
                        | Type::Decimal
                        | Type::Quantity
                        | Type::Bool
                        | Type::String
                        | Type::Name
                )
            } else {
                is_encodable_public_value(&ty)
            };
            if !supported {
                return Err(sem_err(
                    "K2003",
                    format!(
                        "{} does not accept {}",
                        builtin.source_name(),
                        type_help::quoted(&ty)
                    ),
                ));
            }
            crate::ir::entrypoint_return_schema(builtin.source_name(), Some(&ty))
                .map_err(|message| sem_err("K2003", message))?;
            Ok(typed_builtin_call(
                builtin,
                arg_typed,
                if builtin == Builtin::ValueEncode {
                    Type::Bytes
                } else {
                    Type::String
                },
            ))
        }
        Builtin::PointerConstructor(constructor) => {
            let name = constructor.name();
            if arg_typed.len() != 1 {
                return Err(sem_err("K2003", format!("{name} expects one argument")));
            }
            let arg_ty = resolve_struct_type(&arg_typed[0].ty);
            let ty = pointer_constructor_type(constructor);
            if arg_ty != Type::String {
                return Err(sem_err("K2003", format!("{name} expects string")));
            }
            if let ExprKind::String(raw) = arg_typed[0].kind()
                && let Err(invalid) = id_literals::validate(
                    constructor,
                    raw,
                    iroha_data_model::account::address::chain_discriminant(),
                )
            {
                return Err(sem_err("E_INVALID_ID_LITERAL", invalid.message));
            }
            if constructor == PointerConstructor::Json {
                let ExprKind::String(raw) = arg_typed[0].kind() else {
                    return Err(sem_err(
                        "E_JSON_LITERAL_REQUIRED",
                        JSON_LITERAL_REQUIRED_MESSAGE.into(),
                    ));
                };
                parse_json_literal(raw)?;
            }
            Ok(TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Builtin(builtin),
                    args: arg_typed,
                },
                ty,
            })
        }
        Builtin::Contains => {
            if arg_typed.len() != 2 {
                return Err(sem_err(
                    "K2003",
                    "contains expects (StateMap<K,V>, K)".into(),
                ));
            }
            match &arg_typed[0].ty {
                Type::StateMap(k, _v) => {
                    ensure_assignable_and_coerce(&k.clone(), &mut arg_typed[1])?;
                    ensure_in_memory_map_word_types(context, &arg_typed[0])?;
                    Ok(typed_builtin_call(builtin, arg_typed, Type::Bool))
                }
                other => Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "contains expects StateMap<K,V> as first arg, got {}",
                        type_name(other)
                    ),
                }),
            }
        }
        Builtin::GetOrInsert => {
            let in_view = context
                .current_function_modifiers
                .borrow()
                .as_ref()
                .is_some_and(|modifiers| modifiers.kind == FunctionKind::View);
            if in_view {
                return Err(sem_err("K2004", "`view fn` functions cannot use the state-writing map helper `get_or_insert`; read with `map.get(key)` and handle `Option::none`".into()));
            }
            analyze_map_get_or_insert(context, builtin, arg_typed)
        }
        Builtin::RegisterAsset => analyze_register_asset_call(builtin, arg_typed),
        Builtin::GrantContractPermission | Builtin::RevokeContractPermission => {
            analyze_permission_grant_call(context, builtin, arg_typed)
        }
        builtin if builtin.is_compile_time_nominal() => Err(misplaced_nominal_value(builtin)),
        Builtin::StateMapRemove => {
            if arg_typed.len() != 2 {
                return Err(sem_err(
                    "K2003",
                    "StateMap.remove expects exactly one key argument".into(),
                ));
            }
            if !typed_map_expr_is_state(context, &arg_typed[0]) {
                return Err(SemanticError {
                    code: "K2005",
                    message: "StateMap.remove is available only on declared durable state maps"
                        .into(),
                });
            }
            let Type::StateMap(key, value) = resolve_struct_type(&arg_typed[0].ty) else {
                return Err(sem_err(
                    "K2003",
                    "StateMap.remove receiver must be StateMap<K, V>".into(),
                ));
            };
            debug_assert!(is_supported_durable_value_type(&value));
            ensure_assignable_and_coerce(&key, &mut arg_typed[1])?;
            Ok(typed_builtin_call(builtin, arg_typed, Type::Option(value)))
        }
        Builtin::KeysTake2 | Builtin::ValuesTake2 => {
            let name = builtin.name();
            if arg_typed.len() != 3 {
                return Err(sem_err(
                    "K2003",
                    format!("{name} expects (StateMap<int,int>, int start, int which)"),
                ));
            }
            match &arg_typed[0].ty {
                Type::StateMap(k, v)
                    if matches!(resolve_struct_type(k), Type::Int)
                        && matches!(resolve_struct_type(v), Type::Int) => {}
                other => {
                    return Err(SemanticError {
                        code: "K2003",
                        message: format!(
                            "{name} expects StateMap<int,int> as first arg, got {}",
                            type_name(other)
                        ),
                    });
                }
            }
            if !matches!(resolve_struct_type(&arg_typed[1].ty), Type::Int)
                || !matches!(resolve_struct_type(&arg_typed[2].ty), Type::Int)
            {
                return Err(sem_err(
                    "K2003",
                    format!("{name} expects (StateMap<int,int>, int, int)"),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Int))
        }
        Builtin::KeysValuesTake2 => {
            if arg_typed.len() != 3 {
                return Err(sem_err(
                    "K2003",
                    "keys_values_take2 expects (StateMap<int,int>, int, int)".into(),
                ));
            }
            match &arg_typed[0].ty {
                Type::StateMap(k, v)
                    if matches!(resolve_struct_type(k), Type::Int)
                        && matches!(resolve_struct_type(v), Type::Int) => {}
                other => {
                    return Err(SemanticError {
                        code: "K2003",
                        message: format!(
                            "keys_values_take2 expects StateMap<int,int> as first arg, got {}",
                            type_name(other)
                        ),
                    });
                }
            }
            if !matches!(resolve_struct_type(&arg_typed[1].ty), Type::Int)
                || !matches!(resolve_struct_type(&arg_typed[2].ty), Type::Int)
            {
                return Err(sem_err(
                    "K2003",
                    "keys_values_take2 expects (StateMap<int,int>, int, int)".into(),
                ));
            }
            Ok(typed_builtin_call(
                builtin,
                arg_typed,
                Type::Tuple(vec![Type::Int, Type::Int]),
            ))
        }
        Builtin::QueryGetAccount
        | Builtin::QueryGetAsset
        | Builtin::QueryGetAssetDefinition
        | Builtin::QueryGetDomain
        | Builtin::QueryGetNft => {
            if arg_typed.len() != 1 || !query_helper_accepts_arg(builtin, &arg_typed[0].ty) {
                let expected = match builtin {
                    Builtin::QueryGetAccount => "AccountId",
                    Builtin::QueryGetAsset => "AssetId",
                    Builtin::QueryGetAssetDefinition => "AssetDefinitionId",
                    Builtin::QueryGetDomain => "DomainId",
                    Builtin::QueryGetNft => "NftId",
                    _ => unreachable!(),
                };
                return Err(SemanticError {
                    code: "E_QUERY_KEY_TYPE",
                    message: format!(
                        "`{}` expects one `{expected}` argument; byte-returning core-query compatibility is not part of Kotodama V1",
                        builtin.source_name()
                    ),
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Builtin(builtin),
                    args: arg_typed,
                },
                ty: Type::Option(Box::new(
                    core_query_view_type(builtin)
                        .expect("singular projected core-query builtin has a view type"),
                )),
            })
        }
        Builtin::QueryPageAccounts
        | Builtin::QueryPageAssets
        | Builtin::QueryPageAssetsOf
        | Builtin::QueryPageAssetDefinitions
        | Builtin::QueryPageDomains
        | Builtin::QueryPageNfts => {
            let has_owner = builtin == Builtin::QueryPageAssetsOf;
            let first = usize::from(has_owner);
            if arg_typed.len() != first + 2
                || (has_owner && arg_typed[0].ty != Type::AccountId)
                || arg_typed[first].ty != Type::Int
                || arg_typed[first + 1].ty != Type::Int
            {
                return Err(SemanticError {
                    code: "E_QUERY_PAGE_ARGUMENTS",
                    message: format!(
                        "`{}` expects named {}offset: int and limit: int arguments",
                        builtin.source_name(),
                        if has_owner {
                            "account: AccountId, "
                        } else {
                            ""
                        }
                    ),
                });
            }
            if literal_int(&arg_typed[first]).is_some_and(|offset| {
                offset
                    .try_to_i64()
                    .is_none_or(|offset| offset.is_negative())
            }) {
                return Err(SemanticError {
                    code: "E_QUERY_OFFSET",
                    message: "query page offset must be in 0..=i64::MAX".into(),
                });
            }
            if literal_int(&arg_typed[first + 1]).is_some_and(|limit| {
                limit
                    .try_to_u64()
                    .is_none_or(|limit| !(1..=64).contains(&limit))
            }) {
                return Err(SemanticError {
                    code: "E_QUERY_LIMIT",
                    message: "query page limit must be in 1..=64".into(),
                });
            }
            if let (Some(offset), Some(limit)) = (
                literal_int(&arg_typed[first]).and_then(|offset| offset.try_to_i64()),
                literal_int(&arg_typed[first + 1]).and_then(|limit| limit.try_to_i64()),
            ) && offset.checked_add(limit).is_none()
            {
                return Err(SemanticError {
                    code: "E_QUERY_OFFSET",
                    message: "query page offset plus limit must fit i64".into(),
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Builtin(builtin),
                    args: arg_typed,
                },
                ty: core_query_page_type(builtin),
            })
        }
        Builtin::Sm2Verify => {
            if arg_typed.len() != 3 && arg_typed.len() != 4 {
                return Err(sem_err("K2003", "sm2_verify expects (bytes, bytes, bytes) or (bytes, bytes, bytes, bytes) where arguments reference INPUT TLVs".into()));
            }
            if arg_typed[..3].iter().any(|t| !is_blob_like(&t.ty)) {
                return Err(SemanticError {
                    code: "K2003",
                    message:
                        "sm2_verify expects message, signature, and public key as bytes pointers"
                            .into(),
                });
            }
            if arg_typed.len() == 4 && !is_blob_like(&arg_typed[3].ty) {
                return Err(sem_err(
                    "K2003",
                    "sm2_verify optional distid must be provided as bytes pointer".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Bool))
        }
        Builtin::Sm4CcmSeal | Builtin::Sm4CcmOpen => {
            if arg_typed.len() != 4 && arg_typed.len() != 5 {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "{} expects (bytes, bytes, bytes, bytes[, int])",
                        builtin.name()
                    ),
                });
            }
            if arg_typed[..4].iter().any(|t| !is_blob_like(&t.ty)) {
                let data_label = match builtin {
                    Builtin::Sm4CcmSeal => "plaintext",
                    Builtin::Sm4CcmOpen => "ciphertext",
                    _ => unreachable!(),
                };
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "{} expects key, nonce, aad, {data_label} as bytes pointers",
                        builtin.name()
                    ),
                });
            }
            if arg_typed.len() == 5 && !is_int_like(&arg_typed[4].ty) {
                return Err(sem_err(
                    "K2003",
                    format!("{} optional tag length must be int", builtin.name()),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Bytes))
        }
        Builtin::Assert => {
            let ok = match arg_typed.len() {
                1 => arg_typed[0].ty == Type::Bool,
                2 => {
                    arg_typed[0].ty == Type::Bool
                        && (arg_typed[1].ty == Type::String || is_int_like(&arg_typed[1].ty))
                }
                _ => false,
            };
            if !ok {
                return Err(sem_err(
                    "K2003",
                    "assert expects (bool) or (bool, string|int)".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::EscrowOpenOffer => {
            if !(arg_typed.len() == 3 || arg_typed.len() == 4)
                || !(arg_typed[0].ty == Type::Name
                    && arg_typed[1].ty == Type::AssetDefinitionId
                    && arg_typed[2].ty == Type::Quantity)
                || (arg_typed.len() == 4 && !is_blob_like(&arg_typed[3].ty))
            {
                return Err(SemanticError {
                    code: "K2003",
                    message:
                        "escrow_open_offer expects (Name, AssetDefinitionId, quantity[, bytes evidence_hashes])"
                            .into(),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::EscrowOpenDispute => {
            if !(arg_typed.len() == 1 || arg_typed.len() == 2)
                || arg_typed[0].ty != Type::Name
                || (arg_typed.len() == 2 && !is_blob_like(&arg_typed[1].ty))
            {
                return Err(sem_err(
                    "K2003",
                    "escrow_open_dispute expects (Name[, bytes evidence_hashes])".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::EscrowResolveDispute => {
            if !(arg_typed.len() == 3 || arg_typed.len() == 4)
                || !(arg_typed[0].ty == Type::Name
                    && arg_typed[1].ty == Type::Quantity
                    && arg_typed[2].ty == Type::Quantity)
                || (arg_typed.len() == 4 && !is_blob_like(&arg_typed[3].ty))
            {
                return Err(SemanticError {
                    code: "K2003",
                    message: "escrow_resolve_dispute expects (Name, quantity, quantity[, bytes evidence_hashes])"
                        .into(),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::GetMerklePath => {
            let valid_arity = (2..=3).contains(&arg_typed.len());
            if !valid_arity || arg_typed.iter().any(|arg| !is_int_like(&arg.ty)) {
                return Err(SemanticError {
                    code: "K2003",
                    message:
                        "get_merkle_path expects (int address, int output_ptr[, int root_output_ptr])"
                            .into(),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Int))
        }
        Builtin::GetMerkleCompact | Builtin::GetRegisterMerkleCompact => {
            let valid_arity = (2..=4).contains(&arg_typed.len());
            if !valid_arity || arg_typed.iter().any(|arg| !is_int_like(&arg.ty)) {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "{} expects (int address_or_register, int output_ptr[, int max_depth[, int root_output_ptr]])",
                        builtin.name()
                    ),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Int))
        }
        Builtin::GetPrivateInput => {
            if arg_typed.len() != 1 || !is_int_like(&arg_typed[0].ty) {
                return Err(sem_err(
                    "K2003",
                    format!("{} expects (int index)", builtin.source_name()),
                ));
            }
            if !context.zk_enabled {
                return Err(SemanticError {
                    code: "E_ZK_MODE_REQUIRED",
                    message: format!(
                        "{} requires ZK mode in compiler build configuration",
                        builtin.source_name()
                    ),
                });
            }
            let payload = match expected.map(resolve_struct_type) {
                Some(Type::Secret(payload))
                    if matches!(payload.as_ref(), Type::Int | Type::Decimal | Type::Quantity) =>
                {
                    *payload
                }
                Some(other) => {
                    return Err(SemanticError {
                        code: "E_SECRET_PRIVATE_INPUT_CONTEXT",
                        message: format!(
                            "{} must initialize an explicitly declared Secret<int>, Secret<decimal>, or Secret<quantity>; found `{}`",
                            builtin.source_name(),
                            type_name(&other)
                        ),
                    });
                }
                None => {
                    return Err(SemanticError {
                        code: "E_SECRET_PRIVATE_INPUT_AMBIGUOUS",
                        message: format!(
                            "{} has no inferable payload type; use a type-first declaration such as `let Secret<int> value = {}(0)`",
                            builtin.source_name(),
                            builtin.source_name()
                        ),
                    });
                }
            };
            Ok(typed_builtin_call(
                builtin,
                arg_typed,
                Type::Secret(Box::new(payload)),
            ))
        }
        Builtin::TransferBatch => {
            ensure_transfer_batch_args(&arg_typed)?;
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::AxtTouch => {
            if arg_typed.is_empty()
                || arg_typed.len() > 2
                || arg_typed[0].ty != Type::DataSpaceId
                || (arg_typed.len() == 2 && !is_blob_like(&arg_typed[1].ty))
            {
                return Err(sem_err(
                    "K2003",
                    "axt_touch expects (DataSpaceId[, bytes manifest])".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::VerifyDsProof => {
            if arg_typed.is_empty()
                || arg_typed.len() > 2
                || arg_typed[0].ty != Type::DataSpaceId
                || (arg_typed.len() == 2 && arg_typed[1].ty != Type::ProofBlob)
            {
                return Err(sem_err(
                    "K2003",
                    "verify_ds_proof expects (DataSpaceId[, ProofBlob])".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::SetAccountQuorum => {
            if arg_typed.len() != 2
                || !(arg_typed[0].ty == Type::AccountId && arg_typed[1].ty == Type::Int)
            {
                return Err(sem_err(
                    "K2003",
                    "set_account_quorum expects (AccountId, int)".into(),
                ));
            }
            if literal_int(&arg_typed[1]).is_some_and(|quorum| {
                quorum
                    .try_to_u64()
                    .is_none_or(|quorum| !(1..=u64::from(u16::MAX)).contains(&quorum))
            }) {
                return Err(sem_err(
                    "E_QUORUM_RANGE",
                    "account quorum must be in the protocol range 1..=65535".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::TlvLen => {
            if arg_typed.len() != 1 {
                return Err(sem_err("K2003", "tlv_len expects one argument".into()));
            }
            let ty = resolve_struct_type(&arg_typed[0].ty);
            if !(is_pointer_type(&ty) || is_blob_like(&ty) || ty == Type::Json) {
                return Err(sem_err(
                    "K2003",
                    "tlv_len expects a pointer-ABI type, Json, or bytes argument".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Int))
        }
        Builtin::PointerToNorito => {
            if arg_typed.len() != 1 {
                return Err(sem_err(
                    "K2003",
                    "pointer_to_norito expects one argument".into(),
                ));
            }
            let ty = resolve_struct_type(&arg_typed[0].ty);
            if !(is_pointer_type(&ty) || is_blob_like(&ty)) {
                return Err(SemanticError {
                    code: "K2003",
                    message: "pointer_to_norito expects a pointer-ABI type or bytes argument"
                        .into(),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Bytes))
        }
        Builtin::NumericNeg => {
            if arg_typed.len() != 1 || !is_wide_numeric_type(&arg_typed[0].ty) {
                return Err(sem_err(
                    "K2003",
                    "numeric_neg expects (quantity|int)".into(),
                ));
            }
            Err(sem_err(
                "E_QUANTITY_NEGATION",
                "numeric::neg is not defined for int or quantity values".into(),
            ))
        }
        Builtin::NumericNegDirect => {
            if arg_typed.len() != 1 || !is_wide_numeric_type(&arg_typed[0].ty) {
                return Err(sem_err(
                    "K2003",
                    "numeric_neg_direct expects (quantity|int)".into(),
                ));
            }
            Err(sem_err(
                "E_QUANTITY_NEGATION",
                "numeric negation is not defined for int or quantity values".into(),
            ))
        }
        Builtin::NumericAdd
        | Builtin::NumericSub
        | Builtin::NumericMul
        | Builtin::NumericDiv
        | Builtin::NumericRem
        | Builtin::NumericAddDirect
        | Builtin::NumericSubDirect
        | Builtin::NumericMulDirect
        | Builtin::NumericDivDirect
        | Builtin::NumericRemDirect => {
            if arg_typed.len() != 2
                || !is_wide_numeric_type(&arg_typed[0].ty)
                || !is_wide_numeric_type(&arg_typed[1].ty)
            {
                return Err(sem_err(
                    "K2003",
                    format!("{} expects (quantity|int, quantity|int)", builtin.name()),
                ));
            }
            let Some(result_ty) = numeric_result_type(&arg_typed[0].ty, &arg_typed[1].ty) else {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "{} expects compatible wide numeric operands",
                        builtin.name()
                    ),
                });
            };
            if !is_wide_numeric_type(&result_ty) {
                return Err(sem_err(
                    "K2003",
                    format!("{} expects wide numeric operands", builtin.name()),
                ));
            }
            if matches!(resolve_struct_type(&result_ty), Type::Quantity)
                && matches!(builtin, Builtin::NumericRem | Builtin::NumericRemDirect)
            {
                return Err(SemanticError {
                    code: "E_QUANTITY_REMAINDER",
                    message: "quantity does not support `%`; divide with an explicit rounding mode, for example `value.div_round(divisor: d, scale: 6, mode: Rounding::floor)`"
                        .into(),
                });
            }
            if matches!(resolve_struct_type(&result_ty), Type::Quantity)
                && matches!(
                    builtin,
                    Builtin::NumericAddDirect
                        | Builtin::NumericSubDirect
                        | Builtin::NumericMulDirect
                        | Builtin::NumericDivDirect
                        | Builtin::NumericRemDirect
                )
            {
                return Err(SemanticError {
                    code: "K2003",
                    message: "direct Numeric helpers only accept int; quantity uses its nominal V1 syscalls"
                        .into(),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, result_ty))
        }
        Builtin::NumericEq
        | Builtin::NumericNe
        | Builtin::NumericLt
        | Builtin::NumericLe
        | Builtin::NumericGt
        | Builtin::NumericGe
        | Builtin::NumericEqDirect
        | Builtin::NumericNeDirect
        | Builtin::NumericLtDirect
        | Builtin::NumericLeDirect
        | Builtin::NumericGtDirect
        | Builtin::NumericGeDirect => {
            if arg_typed.len() != 2
                || !is_wide_numeric_type(&arg_typed[0].ty)
                || !is_wide_numeric_type(&arg_typed[1].ty)
                || numeric_result_type(&arg_typed[0].ty, &arg_typed[1].ty).is_none()
            {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "{} expects compatible wide numeric operands",
                        builtin.name()
                    ),
                });
            }
            if matches!(resolve_struct_type(&arg_typed[0].ty), Type::Quantity)
                && matches!(
                    builtin,
                    Builtin::NumericEqDirect
                        | Builtin::NumericNeDirect
                        | Builtin::NumericLtDirect
                        | Builtin::NumericLeDirect
                        | Builtin::NumericGtDirect
                        | Builtin::NumericGeDirect
                )
            {
                return Err(SemanticError {
                    code: "K2003",
                    message: "direct Numeric comparisons only accept int; quantity uses its nominal V1 syscalls"
                        .into(),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Bool))
        }
        Builtin::TriggerEvent => {
            reject_public_trigger_event(context, builtin.name())?;
            if !arg_typed.is_empty() {
                return Err(sem_err(
                    "K2003",
                    "trigger_event expects no arguments".into(),
                ));
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Json))
        }
        Builtin::TestSetBlockHeight
        | Builtin::TestAdvanceBlocks
        | Builtin::TestSetTransactionTimeMs => {
            if arg_typed.len() != 1 || !is_int_like(&arg_typed[0].ty) {
                return Err(SemanticError {
                    code: "K2003",
                    message: format!(
                        "`{}` expects one non-negative int ({})",
                        builtin.source_name(),
                        builtin.signature().parameter_names[0]
                    ),
                });
            }
            Ok(typed_builtin_call(builtin, arg_typed, Type::Unit))
        }
        Builtin::TestInvokeEntrypoint
        | Builtin::TestInvokeEntrypointAs
        | Builtin::TestExpectRejectAs
        | Builtin::TestExpectAnyRejectAs
        | Builtin::TestActorAccount
        | Builtin::TestActorPublicKey
        | Builtin::TestActorSign => {
            unreachable!("test helpers are validated before generic builtin analysis")
        }
        _ => analyze_fixed_builtin_call(builtin, arg_typed),
    }
}

fn enclosing_return_type(context: &SemanticContext) -> Option<Type> {
    context
        .current_function_name
        .borrow()
        .as_ref()
        .and_then(|name| context.function_returns.borrow().get(name).cloned())
}
fn typed_block_value_type(block: &TypedBlock) -> Type {
    block
        .tail
        .as_ref()
        .map_or(Type::Unit, |expression| expression.ty.clone())
}
/// Return whether evaluating `block` can never reach its enclosing expression continuation.
///
/// Divergent expression branches behave like a bottom type: they do not need
/// to synthesize a placeholder value merely to agree with a sibling branch.
/// Keeping divergence as a control-flow property instead of a public V1 type
/// also prevents it from leaking into entrypoint schemas or the pointer ABI.
pub(crate) fn typed_block_diverges(block: &TypedBlock) -> bool {
    block.statements.iter().any(typed_statement_diverges)
        || block.tail.as_deref().is_some_and(typed_expression_diverges)
}
fn typed_statement_diverges(statement: &TypedStatement) -> bool {
    match statement {
        TypedStatement::Return(_) | TypedStatement::Break | TypedStatement::Continue => true,
        TypedStatement::If {
            then_branch,
            else_branch: Some(else_branch),
            ..
        }
        | TypedStatement::IfLet {
            then_branch,
            else_branch: Some(else_branch),
            ..
        } => typed_block_diverges(then_branch) && typed_block_diverges(else_branch),
        TypedStatement::Let { value, .. } | TypedStatement::Expr(value) => {
            typed_expression_diverges(value)
        }
        TypedStatement::If {
            else_branch: None, ..
        }
        | TypedStatement::IfLet {
            else_branch: None, ..
        }
        | TypedStatement::While { .. }
        | TypedStatement::For { .. }
        | TypedStatement::ForEachMap { .. }
        | TypedStatement::MapSet { .. } => false,
    }
}
fn typed_expression_diverges(expression: &TypedExpr) -> bool {
    match expression.kind() {
        ExprKind::If {
            then_branch,
            else_branch,
            ..
        }
        | ExprKind::IfLet {
            then_branch,
            else_branch,
            ..
        } => typed_block_diverges(then_branch) && typed_block_diverges(else_branch),
        ExprKind::Match { arms, .. } => {
            !arms.is_empty() && arms.iter().all(|arm| typed_block_diverges(&arm.body))
        }
        _ => false,
    }
}
fn analyze_expression_block(
    context: &SemanticContext,
    block: &Block,
    vars: &mut HashMap<String, Type>,
    expected: Option<&Type>,
    boundary: bool,
) -> Result<TypedBlock, SemanticError> {
    let return_type = enclosing_return_type(context);
    let mut mutable_bindings = context.current_mutable_bindings.borrow().clone();
    analyze_block(
        context,
        block,
        vars,
        &mut mutable_bindings,
        return_type.as_ref(),
        BlockTailContext {
            expected,
            widen: boundary,
        },
        0,
    )
}
fn require_exact_branch_type(expected: &Type, actual: &Type) -> Result<(), SemanticError> {
    if resolve_struct_type(expected) == resolve_struct_type(actual) {
        Ok(())
    } else {
        Err(SemanticError {
            code: "E_BRANCH_TYPE_MISMATCH",
            message: format!(
                "expression branches must have exactly the same type; expected `{}`, found `{}`",
                type_name(expected),
                type_name(actual)
            ),
        })
    }
}
fn normalize_branch_error(error: SemanticError, expected: &Type) -> SemanticError {
    if matches!(
        error.code,
        "E_TAIL_TYPE_MISMATCH" | "E_TYPE_ANNOTATION_MISMATCH"
    ) {
        SemanticError {
            code: "E_BRANCH_TYPE_MISMATCH",
            message: format!(
                "expression branch must have type `{}`: {}",
                type_name(expected),
                error.message
            ),
        }
    } else {
        error
    }
}
fn analyze_expression_branches(
    context: &SemanticContext,
    then_branch: &Block,
    else_branch: &Block,
    vars: &HashMap<String, Type>,
    expected: Option<&Type>,
    boundary: bool,
) -> Result<(TypedBlock, TypedBlock, Type), SemanticError> {
    analyze_expression_branches_with_envs(
        context,
        then_branch,
        else_branch,
        &mut vars.clone(),
        &mut vars.clone(),
        expected,
        boundary,
    )
}
fn analyze_expression_branches_with_envs(
    context: &SemanticContext,
    then_branch: &Block,
    else_branch: &Block,
    then_vars: &mut HashMap<String, Type>,
    else_vars: &mut HashMap<String, Type>,
    expected: Option<&Type>,
    boundary: bool,
) -> Result<(TypedBlock, TypedBlock, Type), SemanticError> {
    if let Some(expected) = expected {
        let then_typed =
            analyze_expression_block(context, then_branch, then_vars, Some(expected), boundary)
                .map_err(|error| normalize_branch_error(error, expected))?;
        let else_typed =
            analyze_expression_block(context, else_branch, else_vars, Some(expected), boundary)
                .map_err(|error| normalize_branch_error(error, expected))?;
        if !typed_block_diverges(&then_typed) {
            require_exact_branch_type(expected, &typed_block_value_type(&then_typed))?;
        }
        if !typed_block_diverges(&else_typed) {
            require_exact_branch_type(expected, &typed_block_value_type(&else_typed))?;
        }
        return Ok((then_typed, else_typed, expected.clone()));
    }
    match analyze_expression_block(context, then_branch, &mut then_vars.clone(), None, boundary) {
        Ok(then_typed) => {
            if typed_block_diverges(&then_typed) {
                let else_typed =
                    analyze_expression_block(context, else_branch, else_vars, None, boundary)?;
                if typed_block_diverges(&else_typed) {
                    return Err(SemanticError {
                        code: "E_DIVERGING_EXPRESSION_CONTEXT",
                        message:
                            "an expression whose branches all return requires an exact type context"
                                .into(),
                    });
                }
                let ty = typed_block_value_type(&else_typed);
                return Ok((then_typed, else_typed, ty));
            }
            let ty = typed_block_value_type(&then_typed);
            let else_typed =
                analyze_expression_block(context, else_branch, else_vars, Some(&ty), boundary)?;
            if !typed_block_diverges(&else_typed) {
                require_exact_branch_type(&ty, &typed_block_value_type(&else_typed))?;
            }
            Ok((then_typed, else_typed, ty))
        }
        Err(error) if error.code == "E_SUM_MISSING_CONTEXT" => {
            context.discard_diagnostic();
            let else_typed =
                analyze_expression_block(context, else_branch, else_vars, None, boundary)?;
            if typed_block_diverges(&else_typed) {
                return Err(error);
            }
            let ty = typed_block_value_type(&else_typed);
            let then_typed =
                analyze_expression_block(context, then_branch, then_vars, Some(&ty), boundary)?;
            if !typed_block_diverges(&then_typed) {
                require_exact_branch_type(&ty, &typed_block_value_type(&then_typed))?;
            }
            Ok((then_typed, else_typed, ty))
        }
        Err(error) => Err(error),
    }
}
fn analyze_sum_pattern(
    context: &SemanticContext,
    pattern: &SumPattern,
    value_type: &Type,
) -> Result<(TypedSumPattern, Option<(String, Type)>), SemanticError> {
    let value_type = resolve_struct_type(value_type);
    let mut variant_code = None;
    let payload = match (&value_type, &pattern.variant) {
        (Type::Option(payload), SumVariant::OptionSome) => Some(payload.as_ref().clone()),
        (Type::Option(_), SumVariant::OptionNone) => None,
        (Type::Result(payload, _), SumVariant::ResultOk) => Some(payload.as_ref().clone()),
        (Type::Result(_, error), SumVariant::ResultErr) => Some(error.as_ref().clone()),
        (Type::Enum(_) | Type::ErrorEnum(_), SumVariant::Nominal { namespace, variant }) => {
            if declared_enum_type(context, namespace).as_ref() != Some(&value_type) {
                return Err(sem_err(
                    "E_PATTERN_FAMILY",
                    format!(
                        "pattern `{namespace}::{variant}` does not belong to `{}`",
                        type_name(&value_type)
                    ),
                ));
            }
            variant_code = Some(nominal_variant_code(&value_type, variant).ok_or_else(|| {
                sem_err(
                    "E_PATTERN_VARIANT",
                    format!("unknown enum variant `{namespace}::{variant}`"),
                )
            })?);
            None
        }
        (Type::Option(_), _) => {
            return Err(SemanticError {
                code: "E_PATTERN_FAMILY",
                message: "Option values require `Option::some`/`Option::none` patterns".into(),
            });
        }
        (Type::Result(_, _), _) => {
            return Err(SemanticError {
                code: "E_PATTERN_FAMILY",
                message: "Result values require `Result::ok`/`Result::err` patterns".into(),
            });
        }
        (other, _) => {
            return Err(SemanticError {
                code: "E_PATTERN_TYPE",
                message: format!(
                    "patterns require Option, Result, or a nominal enum type, found `{}`",
                    type_name(other)
                ),
            });
        }
    };
    let binding = match (&pattern.binding, &payload) {
        (Some(PatternBinding::Name(name)), Some(payload)) => Some((name.clone(), payload.clone())),
        (Some(PatternBinding::Wildcard), Some(_)) | (None, None) => None,
        (None, Some(_)) => {
            return Err(SemanticError {
                code: "E_PATTERN_PAYLOAD",
                message: "active sum patterns require a payload binding or `_`".into(),
            });
        }
        (Some(_), None) => {
            return Err(SemanticError {
                code: "E_PATTERN_PAYLOAD",
                message: "`Option::none` has no payload to bind".into(),
            });
        }
    };
    Ok((
        TypedSumPattern {
            pattern: pattern.clone(),
            variant_code,
            payload_type: payload,
        },
        binding,
    ))
}
fn analyze_match_expression(
    context: &SemanticContext,
    value: TypedExpr,
    arms: &[MatchArm],
    vars: &HashMap<String, Type>,
    expected: Option<&Type>,
    boundary: bool,
) -> Result<TypedExpr, SemanticError> {
    if arms.is_empty() {
        return Err(SemanticError {
            code: "E_MATCH_EMPTY",
            message: "match requires exhaustive arms".into(),
        });
    }
    let mut seen = HashSet::new();
    let mut seen_codes = HashSet::new();
    let mut checked = Vec::with_capacity(arms.len());
    for arm in arms {
        let (pattern, binding) = analyze_sum_pattern(context, &arm.pattern, &value.ty)?;
        if !seen.insert(arm.pattern.variant.clone())
            || pattern
                .variant_code
                .is_some_and(|code| !seen_codes.insert(code))
        {
            return Err(SemanticError {
                code: "E_MATCH_DUPLICATE_PATTERN",
                message: format!(
                    "duplicate or unreachable `{:?}` match arm",
                    arm.pattern.variant
                ),
            });
        }
        checked.push((arm, pattern, binding));
    }
    let exhaustive = match resolve_struct_type(&value.ty) {
        Type::Option(_) => {
            seen.contains(&SumVariant::OptionSome) && seen.contains(&SumVariant::OptionNone)
        }
        Type::Result(_, _) => {
            seen.contains(&SumVariant::ResultOk) && seen.contains(&SumVariant::ResultErr)
        }
        Type::Enum(descriptor) => checked.len() == descriptor.variants.len(),
        Type::ErrorEnum(descriptor) => checked.len() == descriptor.variants.len(),
        _ => false,
    };
    if !exhaustive {
        return Err(SemanticError {
            code: "E_MATCH_NON_EXHAUSTIVE",
            message: "match must cover every namespaced variant of its value".into(),
        });
    }
    let inferred = if let Some(expected) = expected {
        expected.clone()
    } else {
        let mut inferred = None;
        let mut missing_context = None;
        for (arm, _, binding) in &checked {
            let mut arm_vars = vars.clone();
            if let Some((name, ty)) = binding {
                arm_vars.insert(name.clone(), ty.clone());
            }
            match analyze_expression_block(context, &arm.body, &mut arm_vars, None, boundary) {
                Ok(block) => {
                    if !typed_block_diverges(&block) {
                        inferred = Some(typed_block_value_type(&block));
                        break;
                    }
                }
                Err(error) if error.code == "E_SUM_MISSING_CONTEXT" => {
                    context.discard_diagnostic();
                    missing_context.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        inferred.ok_or_else(|| {
            missing_context.unwrap_or_else(|| SemanticError {
                code: "E_DIVERGING_EXPRESSION_CONTEXT",
                message: "a match whose arms all return requires an exact type context".into(),
            })
        })?
    };
    let mut typed_arms = Vec::with_capacity(checked.len());
    for (arm, pattern, binding) in checked {
        let mut arm_vars = vars.clone();
        if let Some((name, ty)) = binding {
            ensure_new_local_binding(context, &name, &arm_vars)?;
            arm_vars.insert(name, ty);
        }
        let body =
            analyze_expression_block(context, &arm.body, &mut arm_vars, Some(&inferred), boundary)?;
        if !typed_block_diverges(&body) {
            require_exact_branch_type(&inferred, &typed_block_value_type(&body))?;
        }
        typed_arms.push(TypedMatchArm { pattern, body });
    }
    Ok(TypedExpr {
        expr: ExprKind::Match {
            value: Box::new(value),
            arms: typed_arms,
        },
        ty: inferred,
    })
}
fn analyze_record_literal(
    context: &SemanticContext,
    expr: &Expr,
    vars: &mut HashMap<String, Type>,
    event: bool,
) -> Result<TypedExpr, SemanticError> {
    let Expr::StructLiteral { name, fields } = expr.kind() else {
        return Err(SemanticError {
            code: "E_EVENT_PAYLOAD",
            message: "emit requires a named event record".into(),
        });
    };
    let declared_event = context.event_names.borrow().contains(name);
    if event != declared_event {
        return Err(SemanticError {
            code: if event {
                "E_UNKNOWN_EVENT"
            } else {
                "E_EVENT_VALUE"
            },
            message: if event {
                format!("`{name}` is not a declared native event")
            } else {
                format!("event `{name}` can only be constructed by `emit {name} {{ ... }};`")
            },
        });
    }
    context.validate_struct_literal_target(expr, name)?;
    let canonical_name = context
        .resolved_named_types
        .borrow()
        .get(name)
        .and_then(|ty| match ty {
            Type::Struct { name, .. } => Some(name.clone()),
            _ => None,
        })
        .unwrap_or_else(|| name.clone());
    let Some(declared_fields) = context.structs.borrow().get(name).cloned() else {
        return Err(SemanticError {
            code: "E_UNKNOWN_STRUCT",
            message: format!("unknown struct type `{name}`"),
        });
    };
    analyze_record_fields(context, name, canonical_name, fields, declared_fields, vars)
}
fn analyze_record_fields(
    context: &SemanticContext,
    name: &str,
    canonical_name: String,
    fields: &[StructLiteralField],
    declared_fields: Vec<(String, Type)>,
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    for (index, field) in fields.iter().enumerate() {
        if fields[..index]
            .iter()
            .any(|previous| previous.name == field.name)
        {
            return Err(SemanticError {
                code: "E_DUPLICATE_STRUCT_FIELD",
                message: format!("struct field `{}` is supplied more than once", field.name),
            });
        }
        if !declared_fields
            .iter()
            .any(|(declared, _)| declared == &field.name)
        {
            if let Some(suggestion) = crate::diagnostic::suggest::closest(
                &field.name,
                declared_fields
                    .iter()
                    .map(|(declared, _)| declared.as_str()),
            ) {
                context.capture_help(
                    context.expression_source(&field.value),
                    format!("did you mean `{suggestion}`?"),
                );
            }
            return Err(SemanticError {
                code: "E_UNKNOWN_STRUCT_FIELD",
                message: format!("struct `{name}` has no field named `{}`", field.name),
            });
        }
    }
    for (declared_name, _) in &declared_fields {
        if !fields.iter().any(|field| &field.name == declared_name) {
            return Err(SemanticError {
                code: "E_MISSING_STRUCT_FIELD",
                message: format!("struct `{name}` literal is missing field `{declared_name}`"),
            });
        }
    }
    let mut typed_fields = Vec::with_capacity(declared_fields.len());
    for field in fields {
        let (declared_name, declared_ty) = declared_fields
            .iter()
            .find(|(declared, _)| declared == &field.name)
            .expect("unknown struct fields were rejected above");
        let mut value = analyze_expr_in_context(
            context,
            &field.value,
            vars,
            Some(declared_ty),
            canonical_name.starts_with("$arguments::"),
        )?;
        if canonical_name.starts_with("$arguments::") {
            ensure_boundary_assignable_and_coerce(declared_ty, &mut value)?;
        } else {
            ensure_assignable_and_coerce(declared_ty, &mut value)?;
        }
        typed_fields.push((declared_name.clone(), value));
    }
    Ok(TypedExpr {
        expr: ExprKind::StructLiteral {
            name: canonical_name.clone(),
            fields: typed_fields,
        },
        ty: Type::Struct {
            name: canonical_name,
            fields: Arc::from(declared_fields),
        },
    })
}

fn analyze_expr(
    context: &SemanticContext,
    expr: &Expr,
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    analyze_expr_expected(context, expr, vars, None)
}
fn analyze_list_literal(
    context: &SemanticContext,
    elements: &[Expr],
    vars: &mut HashMap<String, Type>,
    expected: Option<&Type>,
) -> Result<TypedExpr, SemanticError> {
    let expected = expected.map(resolve_struct_type);
    let (expected_element, capacity) = match expected {
        Some(Type::List(element, capacity)) => (Some(*element), capacity),
        Some(other) => {
            return Err(SemanticError {
                code: "E_LIST_CONTEXT_TYPE",
                message: format!("a list literal cannot initialize `{}`", type_name(&other)),
            });
        }
        None if elements.is_empty() => {
            return Err(SemanticError {
                code: "E_LIST_EMPTY_CONTEXT",
                message: "an empty list requires an exact `List<T, N>` type context".into(),
            });
        }
        None => {
            let capacity = u8::try_from(elements.len())
                .ok()
                .filter(|capacity| *capacity <= 64)
                .ok_or_else(|| SemanticError {
                    code: "E_LIST_CAPACITY",
                    message: format!(
                        "a list literal with {} elements exceeds the V1 capacity limit of 64",
                        elements.len()
                    ),
                })?;
            (None, capacity)
        }
    };
    if elements.len() > usize::from(capacity) {
        return Err(SemanticError {
            code: "E_LIST_LITERAL_CAPACITY",
            message: format!(
                "list literal has {} elements but its contextual capacity is {capacity}",
                elements.len()
            ),
        });
    }
    let mut typed = Vec::with_capacity(elements.len());
    let mut element_type = expected_element;
    for element in elements {
        let mut value = analyze_expr_expected(context, element, vars, element_type.as_ref())?;
        if let Some(expected_element) = &element_type {
            ensure_assignable_and_coerce(expected_element, &mut value)?;
        } else {
            element_type = Some(resolve_struct_type(&value.ty));
        }
        typed.push(value);
    }
    let element_type = element_type.expect("non-empty uncontextualized list inferred an element");
    if list_element_contains_resource_handle(&element_type) {
        return Err(SemanticError {
            code: "E_LIST_RESOURCE_ELEMENT",
            message: format!(
                "List elements cannot contain resource handle type `{}`",
                type_name(&element_type)
            ),
        });
    }
    let list_type = Type::List(Box::new(element_type), capacity);

    Ok(TypedExpr {
        expr: ExprKind::List(typed),
        ty: list_type,
    })
}
fn analyze_list_comprehension(
    context: &SemanticContext,
    expression: &Expr,
    item: &str,
    source: &Expr,
    condition: Option<&Expr>,
    vars: &mut HashMap<String, Type>,
    expected: Option<&Type>,
) -> Result<TypedExpr, SemanticError> {
    let source = analyze_expr(context, source, vars)?;
    let Type::List(source_element, source_capacity) = resolve_struct_type(&source.ty) else {
        return Err(SemanticError {
            code: "E_LIST_COMPREHENSION_SOURCE",
            message: format!(
                "list comprehension source must be `List<T, N>`, found `{}`",
                type_name(&source.ty)
            ),
        });
    };
    ensure_new_local_binding(context, item, vars)?;
    let (expected_element, result_capacity) = match expected.map(resolve_struct_type) {
        Some(Type::List(element, capacity)) => {
            if source_capacity > capacity {
                context
                    .required_list_capacity
                    .replace(Some(source_capacity));
                return Err(SemanticError {
                    code: "E_LIST_COMPREHENSION_CAPACITY",
                    message: format!(
                        "source capacity {source_capacity} may exceed contextual capacity {capacity}; filters do not reduce the proven maximum"
                    ),
                });
            }
            (Some(*element), capacity)
        }
        Some(other) => {
            return Err(SemanticError {
                code: "E_LIST_CONTEXT_TYPE",
                message: format!(
                    "a list comprehension cannot initialize `{}`",
                    type_name(&other)
                ),
            });
        }
        None => (None, source_capacity),
    };
    let mut comprehension_vars = vars.clone();
    comprehension_vars.insert(item.to_owned(), (*source_element).clone());
    let mut expression = analyze_expr_expected(
        context,
        expression,
        &mut comprehension_vars,
        expected_element.as_ref(),
    )?;
    if let Some(expected_element) = &expected_element {
        ensure_assignable_and_coerce(expected_element, &mut expression)?;
    }
    let element_type = expected_element.unwrap_or_else(|| resolve_struct_type(&expression.ty));
    if list_element_contains_resource_handle(&element_type) {
        return Err(SemanticError {
            code: "E_LIST_RESOURCE_ELEMENT",
            message: format!(
                "List elements cannot contain resource handle type `{}`",
                type_name(&element_type)
            ),
        });
    }
    let list_type = Type::List(Box::new(element_type), result_capacity);

    let condition = condition
        .map(|condition| analyze_expr(context, condition, &mut comprehension_vars))
        .transpose()?;
    if let Some(condition) = &condition {
        crate::secret::reject_secret_control_flow(condition)?;
        if resolve_struct_type(&condition.ty) != Type::Bool {
            return Err(SemanticError {
                code: "E_LIST_COMPREHENSION_FILTER",
                message: "comprehension filter must be bool".into(),
            });
        }
    }
    Ok(TypedExpr {
        expr: ExprKind::ListComprehension {
            expression: Box::new(expression),
            item: item.to_owned(),
            source: Box::new(source),
            condition: condition.map(Box::new),
        },
        ty: list_type,
    })
}
fn is_native_json_value_type(ty: &Type) -> bool {
    match resolve_struct_type(ty) {
        Type::Int
        | Type::Decimal
        | Type::Quantity
        | Type::Bool
        | Type::String
        | Type::Bytes
        | Type::DataSpaceId
        | Type::AccountId
        | Type::AssetDefinitionId
        | Type::AssetId
        | Type::NftId
        | Type::DomainId
        | Type::Name
        | Type::Json
        | Type::Unit
        | Type::Enum(_)
        | Type::ErrorEnum(_)
        | Type::StateCursor(_) => true,
        Type::Option(inner) | Type::List(inner, _) => is_native_json_value_type(&inner),
        Type::AxtDescriptor
        | Type::AxtAnchoredSpendV1
        | Type::ProofBlob
        | Type::SoracloudRequest
        | Type::SoracloudResponse
        | Type::Secret(_)
        | Type::StateMap(_, _)
        | Type::Result(_, _)
        | Type::Tuple(_)
        | Type::Struct { .. }
        | Type::NamedStruct(_)
        | Type::ContractRef(_) => false,
    }
}
fn analyze_native_json_value(
    context: &SemanticContext,
    expression: &Expr,
    vars: &mut HashMap<String, Type>,
) -> Result<TypedExpr, SemanticError> {
    let typed = analyze_expr(context, expression, vars)?;
    if !is_native_json_value_type(&typed.ty) {
        return Err(SemanticError {
            code: "E_JSON_VALUE_TYPE",
            message: format!(
                "native JSON construction cannot convert `{}` implicitly; handle Result and arbitrary structs/tuples explicitly, and keep resource handles outside JSON",
                type_name(&typed.ty)
            ),
        });
    }
    Ok(typed)
}
fn analyze_list_method_call(
    context: &SemanticContext,
    source_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    vars: &mut HashMap<String, Type>,
) -> Option<Result<TypedExpr, SemanticError>> {
    if !implicit_receiver || args.is_empty() {
        return None;
    }
    let method = match source_name {
        "len" => (CompilerIntrinsic::ListLen, &[][..]),
        STATE_MAP_GET_INTRINSIC | "get" => (CompilerIntrinsic::ListGet, &["index"][..]),
        "set" => (CompilerIntrinsic::ListSet, &["index", "value"][..]),
        "push" => (CompilerIntrinsic::ListPush, &["value"][..]),
        "try_set" => (CompilerIntrinsic::ListTrySet, &["index", "value"][..]),
        "try_push" => (CompilerIntrinsic::ListTryPush, &["value"][..]),
        "pop" => (CompilerIntrinsic::ListPop, &[][..]),
        "contains" => (CompilerIntrinsic::ListContains, &["value"][..]),
        "take" => (CompilerIntrinsic::ListTake, &["limit"][..]),
        "enumerate" => (CompilerIntrinsic::ListEnumerate, &[][..]),
        _ => return None,
    };
    let receiver = match analyze_expr(context, &args[0], vars) {
        Ok(receiver) => receiver,
        Err(error) => return Some(Err(error)),
    };
    let Type::List(element, capacity) = resolve_struct_type(&receiver.ty) else {
        return None;
    };
    if matches!(
        method.0,
        CompilerIntrinsic::ListSet
            | CompilerIntrinsic::ListPush
            | CompilerIntrinsic::ListTrySet
            | CompilerIntrinsic::ListTryPush
            | CompilerIntrinsic::ListPop
    ) {
        // A member chain names one stable local place. Computed temporaries and
        // durable roots require an explicit copy and write-back instead.
        let mut receiver_root = &args[0];
        while let Expr::Member { object, .. } = receiver_root.kind() {
            receiver_root = object;
        }
        let Expr::Ident(receiver_name) = receiver_root.kind() else {
            return Some(Err(SemanticError {
                code: "E_LIST_MUTABLE_RECEIVER",
                message: format!(
                    "List.{source_name} mutates its receiver; call it on a `var` list binding or a field of a `var` product"
                ),
            }));
        };
        let receiver_is_mutable =
            match context.list_receiver_is_mutable(receiver_root, receiver_name, vars) {
                Ok(receiver_is_mutable) => receiver_is_mutable,
                Err(error) => return Some(Err(error)),
            };
        if !receiver_is_mutable {
            return Some(Err(SemanticError {
                code: "E_LIST_MUTABLE_RECEIVER",
                message: format!(
                    "List.{source_name} requires mutable receiver `{receiver_name}`; declare it with `var`"
                ),
            }));
        }
    }
    let parameter_names = method
        .1
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let plan = match reorder_flexible_call_arguments(
        source_name,
        args,
        argument_names,
        true,
        &parameter_names,
        &vec![true; parameter_names.len()],
    ) {
        Ok(plan) => plan,
        Err(error) => return Some(Err(error)),
    };
    let expected_arity = parameter_names.len() + 1;
    if plan.ordered.len() != expected_arity {
        return Some(Err(SemanticError {
            code: "E_LIST_METHOD_ARITY",
            message: format!(
                "List.{} expects {} argument{}, got {}",
                source_name,
                parameter_names.len(),
                if parameter_names.len() == 1 { "" } else { "s" },
                plan.ordered.len().saturating_sub(1)
            ),
        }));
    }
    let mut typed_slots = (0..plan.ordered.len()).map(|_| None).collect::<Vec<_>>();
    typed_slots[0] = Some(receiver);
    for index in plan
        .evaluation_order
        .iter()
        .copied()
        .filter(|index| *index != 0)
    {
        let argument = &plan.ordered[index];
        let typed = match method.0 {
            CompilerIntrinsic::ListTake => match static_integer_constant(context, argument) {
                Ok(value) => value,
                Err(error) => {
                    return Some(Err(SemanticError {
                        code: "E_LIST_TAKE_CONST",
                        message: error.message,
                    }));
                }
            },
            CompilerIntrinsic::ListGet => {
                let argument = match analyze_expr(context, argument, vars) {
                    Ok(argument) => argument,
                    Err(error) => return Some(Err(error)),
                };
                if resolve_struct_type(&argument.ty) != Type::Int {
                    return Some(Err(SemanticError {
                        code: "E_LIST_INDEX_TYPE",
                        message: format!("List.{} expects an int index or limit", source_name),
                    }));
                }
                argument
            }
            CompilerIntrinsic::ListSet | CompilerIntrinsic::ListTrySet if index == 1 => {
                let argument = match analyze_expr(context, argument, vars) {
                    Ok(argument) => argument,
                    Err(error) => return Some(Err(error)),
                };
                if resolve_struct_type(&argument.ty) != Type::Int {
                    return Some(Err(SemanticError {
                        code: "E_LIST_INDEX_TYPE",
                        message: "List.try_set expects an int index".into(),
                    }));
                }
                argument
            }
            CompilerIntrinsic::ListSet
            | CompilerIntrinsic::ListPush
            | CompilerIntrinsic::ListTrySet
            | CompilerIntrinsic::ListTryPush
            | CompilerIntrinsic::ListContains => {
                let mut argument =
                    match analyze_expr_expected(context, argument, vars, Some(&element)) {
                        Ok(argument) => argument,
                        Err(error) => return Some(Err(error)),
                    };
                if let Err(error) = ensure_assignable_and_coerce(&element, &mut argument) {
                    return Some(Err(error));
                }
                argument
            }
            _ => unreachable!("zero-argument methods have no arguments to analyze"),
        };
        typed_slots[index] = Some(typed);
    }
    let typed = match typed_slots
        .into_iter()
        .enumerate()
        .map(|(index, argument)| {
            argument.ok_or_else(|| SemanticError {
                code: "E_MALFORMED_CALL",
                message: format!("List.{source_name} did not analyze argument slot {index}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(typed) => typed,
        Err(error) => return Some(Err(error)),
    };
    let result_type = match method.0 {
        CompilerIntrinsic::ListLen => Type::Int,
        CompilerIntrinsic::ListGet | CompilerIntrinsic::ListPop => Type::Option(element.clone()),
        CompilerIntrinsic::ListSet | CompilerIntrinsic::ListPush => Type::Unit,
        CompilerIntrinsic::ListTrySet | CompilerIntrinsic::ListTryPush => Type::Result(
            Box::new(Type::Unit),
            Box::new(Type::ErrorEnum(Arc::new(
                ivm_abi::error_types::list_error_type(),
            ))),
        ),
        CompilerIntrinsic::ListContains => {
            if !is_eq_comparable_type(&element) {
                return Some(Err(SemanticError {
                    code: "E_LIST_CONTAINS_COMPARABILITY",
                    message: format!(
                        "List.contains requires a canonically comparable element type, found `{}`",
                        type_name(&element)
                    ),
                }));
            }
            Type::Bool
        }
        CompilerIntrinsic::ListTake => {
            let Some(limit) = typed.get(1).and_then(|argument| match argument.kind() {
                ExprKind::IntLiteral(limit) => Some(limit),
                _ => None,
            }) else {
                return Some(Err(SemanticError {
                    code: "E_LIST_TAKE_CONST",
                    message: "List.take limit must be a compile-time integer constant".into(),
                }));
            };
            let limit = match limit
                .try_to_u64()
                .and_then(|limit| u8::try_from(limit).ok())
                .filter(|limit| *limit <= capacity)
            {
                Some(limit) => limit,
                None => {
                    return Some(Err(SemanticError {
                        code: "E_LIST_TAKE_LIMIT",
                        message: format!(
                            "List.take limit {limit} is outside 0..={capacity} for this source List"
                        ),
                    }));
                }
            };
            // V1 List schemas have capacities in 1..=64. `take(0)` is still
            // useful and deterministically produces an empty value, represented
            // by the smallest valid static result capacity.
            Type::List(element.clone(), limit.max(1))
        }
        CompilerIntrinsic::ListEnumerate => Type::List(
            Box::new(Type::Tuple(vec![Type::Int, (*element).clone()])),
            capacity,
        ),
        _ => unreachable!("known List intrinsic"),
    };
    Some(Ok(retain_named_call_evaluation_order(
        TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Intrinsic(method.0),
                args: typed,
            },
            ty: result_type,
        },
        &plan,
    )))
}
fn numeric_rounding_mode(expression: &Expr) -> Option<(RoundingMode, i64)> {
    use ivm_abi::numeric::RoundingModeV1 as AbiMode;
    let (mode, tag) = match expression {
        Expr::Source { expression, .. } | Expr::Resolved { expression, .. } => {
            return numeric_rounding_mode(expression);
        }
        Expr::Ident(name) if name == "Rounding::toward_zero" => {
            (RoundingMode::TowardZero, AbiMode::TowardZero.tag())
        }
        Expr::Ident(name) if name == "Rounding::away_from_zero" => {
            (RoundingMode::AwayFromZero, AbiMode::AwayFromZero.tag())
        }
        Expr::Ident(name) if name == "Rounding::floor" => {
            (RoundingMode::Floor, AbiMode::Floor.tag())
        }
        Expr::Ident(name) if name == "Rounding::ceil" => (RoundingMode::Ceil, AbiMode::Ceil.tag()),
        Expr::Ident(name) if name == "Rounding::nearest_even" => {
            (RoundingMode::NearestEven, AbiMode::NearestEven.tag())
        }
        Expr::Ident(name) if name == "Rounding::nearest_away" => {
            (RoundingMode::NearestAway, AbiMode::NearestAway.tag())
        }
        Expr::Ident(name) if name == "Rounding::nearest_toward_zero" => (
            RoundingMode::NearestTowardZero,
            AbiMode::NearestTowardZero.tag(),
        ),
        _ => return None,
    };
    i64::try_from(tag).ok().map(|tag| (mode, tag))
}
fn analyze_decimal_to_int_round_call(
    context: &SemanticContext,
    source_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    vars: &mut HashMap<String, Type>,
) -> Option<Result<TypedExpr, SemanticError>> {
    if source_name != "decimal::to_int_round" || implicit_receiver {
        return None;
    }
    let names = ["value".to_owned(), "mode".to_owned()];
    let plan = match reorder_flexible_call_arguments(
        source_name,
        args,
        argument_names,
        false,
        &names,
        &[true, true],
    ) {
        Ok(plan) => plan,
        Err(error) => return Some(Err(error)),
    };
    if plan.ordered.len() != 2 {
        return Some(Err(SemanticError {
            code: "E_NUMERIC_ROUND_ARITY",
            message: "decimal::to_int_round expects value and mode".into(),
        }));
    }
    let mut value =
        match analyze_expr_expected(context, &plan.ordered[0], vars, Some(&Type::Decimal)) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
    if let Err(error) = ensure_assignable_and_coerce(&Type::Decimal, &mut value) {
        return Some(Err(error));
    }
    let Some((rounding, tag)) = numeric_rounding_mode(&plan.ordered[1]) else {
        return Some(Err(SemanticError {
            code: "E_NUMERIC_ROUNDING_MODE",
            message: format!(
                "decimal::to_int_round mode must be one of {}",
                V1_ROUNDING_PATHS.join(", ")
            ),
        }));
    };
    if let Ok(Some(crate::checked_arithmetic::ConstantNumeric::Decimal(constant))) =
        crate::checked_arithmetic::evaluate(&value)
    {
        let integer = match constant.decimal_to_int_round(rounding) {
            Ok(integer) => integer,
            Err(error) => {
                let error = crate::checked_arithmetic::ConstantNumericError::Numeric(error);
                return Some(Err(SemanticError {
                    code: error.code(),
                    message: error.to_string(),
                }));
            }
        };
        return Some(Ok(TypedExpr {
            expr: ExprKind::IntLiteral(integer),
            ty: Type::Int,
        }));
    }
    let mode = TypedExpr {
        expr: ExprKind::IntLiteral(BigInt::from(tag)),
        ty: Type::Int,
    };
    Some(Ok(retain_named_call_evaluation_order(
        TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Intrinsic(CompilerIntrinsic::DecimalToIntRound),
                args: vec![value, mode],
            },
            ty: Type::Int,
        },
        &plan,
    )))
}
fn analyze_numeric_mul_div_method_call(
    context: &SemanticContext,
    name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    vars: &mut HashMap<String, Type>,
) -> Option<Result<TypedExpr, SemanticError>> {
    if !implicit_receiver || name != "mul_div_round" || args.is_empty() {
        return None;
    }
    Some((|| {
        use crate::checked_arithmetic::{ConstantNumeric, ConstantNumericError};
        let receiver = analyze_expr(context, &args[0], vars)?;
        let result_type = resolve_struct_type(&receiver.ty);
        let intrinsic = match result_type {
            Type::Decimal => CompilerIntrinsic::DecimalMulDivRound,
            Type::Quantity => CompilerIntrinsic::QuantityMulDivRound,
            _ => {
                return Err(sem_err(
                    "E_NUMERIC_ROUND_RECEIVER",
                    format!(
                        "mul_div_round requires decimal or quantity, found `{}`",
                        type_name(&result_type)
                    ),
                ));
            }
        };
        let names = ["multiplier", "divisor", "scale", "mode"].map(str::to_owned);
        let plan =
            reorder_flexible_call_arguments(name, args, argument_names, true, &names, &[true; 4])?;
        if plan.ordered.len() != 5 {
            return Err(sem_err(
                "E_NUMERIC_ROUND_ARITY",
                "mul_div_round expects multiplier, divisor, scale, and mode".into(),
            ));
        }
        let mut slots = vec![None; 5];
        slots[0] = Some(receiver);
        let mut rounding = None;
        for index in plan
            .evaluation_order
            .iter()
            .copied()
            .filter(|index| *index != 0)
        {
            slots[index] = Some(if index == 4 {
                let (mode, tag) = numeric_rounding_mode(&plan.ordered[index]).ok_or_else(|| {
                    sem_err(
                        "E_NUMERIC_ROUNDING_MODE",
                        format!(
                            "mul_div_round mode must be one of {}",
                            V1_ROUNDING_PATHS.join(", ")
                        ),
                    )
                })?;
                rounding = Some(mode);
                TypedExpr {
                    expr: ExprKind::IntLiteral(BigInt::from(tag)),
                    ty: Type::Int,
                }
            } else {
                let expected = if index == 3 { Type::Int } else { Type::Decimal };
                let mut value =
                    analyze_expr_expected(context, &plan.ordered[index], vars, Some(&expected))?;
                ensure_assignable_and_coerce(&expected, &mut value)?;
                value
            });
        }
        let typed = slots
            .into_iter()
            .map(|slot| slot.expect("all fused argument slots evaluated"))
            .collect::<Vec<_>>();
        let scale = if let ExprKind::IntLiteral(scale) = &typed[3].expr {
            Some(
                scale
                    .try_to_u64()
                    .filter(|scale| *scale <= 28)
                    .ok_or_else(|| {
                        sem_err(
                            "E_INVALID_SCALE",
                            "rounded numeric scale must be in 0..=28".into(),
                        )
                    })? as u32,
            )
        } else {
            None
        };
        if numeric_literal_is_zero(&typed[2]) {
            return Err(sem_err(
                "E_DIVISION_BY_ZERO",
                "mul_div_round divisor must not be zero".into(),
            ));
        }
        if let Some(scale) = scale {
            let values = typed[..3]
                .iter()
                .map(crate::checked_arithmetic::evaluate)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| sem_err(error.code(), error.to_string()))?;
            if let [
                Some(lhs),
                Some(ConstantNumeric::Decimal(multiplier)),
                Some(ConstantNumeric::Decimal(divisor)),
            ] = values.as_slice()
            {
                let mode = rounding.expect("explicit fused rounding mode");
                let result = match lhs {
                    ConstantNumeric::Decimal(value) => {
                        value.try_decimal_mul_div_round(multiplier, divisor, scale, mode)
                    }
                    ConstantNumeric::Quantity(value) => value
                        .try_mul_div_decimal_round(multiplier, divisor, scale, mode)
                        .map(|value| value.into_numeric()),
                    _ => unreachable!("typed fused receiver"),
                }
                .map_err(|error| {
                    let error = ConstantNumericError::Numeric(error);
                    sem_err(error.code(), error.to_string())
                })?;
                return Ok(TypedExpr {
                    expr: ExprKind::DecimalLiteral {
                        spelling: result.to_string(),
                        value: result,
                    },
                    ty: result_type,
                });
            }
        }
        Ok(retain_named_call_evaluation_order(
            TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Intrinsic(intrinsic),
                    args: typed,
                },
                ty: result_type,
            },
            &plan,
        ))
    })())
}
fn analyze_numeric_round_method_call(
    context: &SemanticContext,
    source_name: &str,
    args: &[Expr],
    argument_names: Option<&[Option<String>]>,
    implicit_receiver: bool,
    vars: &mut HashMap<String, Type>,
) -> Option<Result<TypedExpr, SemanticError>> {
    if !implicit_receiver || args.is_empty() || !matches!(source_name, "div_round" | "ratio_round")
    {
        return None;
    }
    let receiver = match analyze_expr(context, &args[0], vars) {
        Ok(receiver) => receiver,
        Err(error) => return Some(Err(error)),
    };
    let receiver_type = resolve_struct_type(&receiver.ty);
    let (divisor_type, result_type, intrinsic, display_name) = match (source_name, &receiver_type) {
        ("div_round", Type::Decimal) => (
            Type::Decimal,
            Type::Decimal,
            CompilerIntrinsic::DecimalDivRound,
            "decimal.div_round",
        ),
        ("div_round", Type::Quantity) => (
            Type::Decimal,
            Type::Quantity,
            CompilerIntrinsic::QuantityDivRound,
            "quantity.div_round",
        ),
        ("ratio_round", Type::Quantity) => (
            Type::Quantity,
            Type::Decimal,
            CompilerIntrinsic::QuantityRatioRound,
            "quantity.ratio_round",
        ),
        _ => {
            return Some(Err(SemanticError {
                code: "E_NUMERIC_ROUND_RECEIVER",
                message: format!(
                    "{source_name} is not defined for receiver type `{}`",
                    type_name(&receiver_type)
                ),
            }));
        }
    };
    let parameter_names = ["divisor", "scale", "mode"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let plan = match reorder_flexible_call_arguments(
        display_name,
        args,
        argument_names,
        true,
        &parameter_names,
        &[true, true, true],
    ) {
        Ok(plan) => plan,
        Err(error) => return Some(Err(error)),
    };
    if plan.ordered.len() != 4 {
        return Some(Err(SemanticError {
            code: "E_NUMERIC_ROUND_ARITY",
            message: format!(
                "{display_name} expects divisor, scale, and mode, got {} argument(s)",
                plan.ordered.len().saturating_sub(1)
            ),
        }));
    }
    let mut typed_slots = (0..4).map(|_| None).collect::<Vec<_>>();
    typed_slots[0] = Some(receiver);
    let mut rounding_mode = None;
    for index in plan
        .evaluation_order
        .iter()
        .copied()
        .filter(|index| *index != 0)
    {
        let typed = match index {
            1 => {
                let mut divisor = match analyze_expr_expected(
                    context,
                    &plan.ordered[index],
                    vars,
                    Some(&divisor_type),
                ) {
                    Ok(divisor) => divisor,
                    Err(error) => return Some(Err(error)),
                };
                if let Err(error) = ensure_assignable_and_coerce(&divisor_type, &mut divisor) {
                    return Some(Err(error));
                }
                divisor
            }
            2 => match analyze_expr_expected(context, &plan.ordered[index], vars, Some(&Type::Int))
            {
                Ok(scale) => scale,
                Err(error) => return Some(Err(error)),
            },
            3 => {
                let Some((mode, mode_tag)) = numeric_rounding_mode(&plan.ordered[index]) else {
                    return Some(Err(SemanticError {
                        code: "E_NUMERIC_ROUNDING_MODE",
                        message: format!(
                            "{display_name} mode must be one of {}",
                            V1_ROUNDING_PATHS.join(", ")
                        ),
                    }));
                };
                rounding_mode = Some(mode);
                TypedExpr {
                    expr: ExprKind::IntLiteral(BigInt::from(mode_tag)),
                    ty: Type::Int,
                }
            }
            _ => unreachable!("rounded division has exactly four ABI slots"),
        };
        typed_slots[index] = Some(typed);
    }
    let mut typed = match typed_slots
        .into_iter()
        .enumerate()
        .map(|(index, argument)| {
            argument.ok_or_else(|| SemanticError {
                code: "E_MALFORMED_CALL",
                message: format!("{display_name} did not analyze argument slot {index}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(typed) => typed,
        Err(error) => return Some(Err(error)),
    };
    let receiver = typed.remove(0);
    let divisor = typed.remove(0);
    let scale = typed.remove(0);
    let mode = typed.remove(0);
    if let ExprKind::IntLiteral(scale_value) = scale.kind()
        && scale_value
            .try_to_u64()
            .is_none_or(|scale_value| scale_value > 28)
    {
        return Some(Err(SemanticError {
            code: "E_INVALID_SCALE",
            message: format!("rounded numeric scale {scale_value} is outside 0..=28"),
        }));
    }
    let rounding_mode = rounding_mode.expect("validated rounding mode slot");
    if numeric_literal_is_zero(&divisor) {
        return Some(Err(SemanticError {
            code: "E_DIVISION_BY_ZERO",
            message: format!("{display_name} divisor must not be zero"),
        }));
    }
    let constant_scale = match scale.kind() {
        ExprKind::IntLiteral(scale) => scale
            .try_to_u64()
            .and_then(|scale| u32::try_from(scale).ok()),
        _ => None,
    };
    if let Some(output_scale) = constant_scale {
        use crate::checked_arithmetic::{ConstantNumeric, ConstantNumericError};
        let lhs = match crate::checked_arithmetic::evaluate(&receiver) {
            Ok(value) => value,
            Err(error) => {
                return Some(Err(SemanticError {
                    code: error.code(),
                    message: error.to_string(),
                }));
            }
        };
        let rhs = match crate::checked_arithmetic::evaluate(&divisor) {
            Ok(value) => value,
            Err(error) => {
                return Some(Err(SemanticError {
                    code: error.code(),
                    message: error.to_string(),
                }));
            }
        };
        let folded = match (intrinsic, lhs, rhs) {
            (
                CompilerIntrinsic::DecimalDivRound,
                Some(ConstantNumeric::Decimal(lhs)),
                Some(ConstantNumeric::Decimal(rhs)),
            ) => lhs
                .try_decimal_div_round(&rhs, output_scale, rounding_mode)
                .map(ConstantNumeric::Decimal),
            (
                CompilerIntrinsic::QuantityDivRound,
                Some(ConstantNumeric::Quantity(lhs)),
                Some(ConstantNumeric::Decimal(rhs)),
            ) => lhs
                .try_div_decimal_round(&rhs, output_scale, rounding_mode)
                .map(ConstantNumeric::Quantity),
            (
                CompilerIntrinsic::QuantityRatioRound,
                Some(ConstantNumeric::Quantity(lhs)),
                Some(ConstantNumeric::Quantity(rhs)),
            ) => lhs
                .try_ratio_round(&rhs, output_scale, rounding_mode)
                .map(ConstantNumeric::Decimal),
            (_, None, _) | (_, _, None) => {
                return Some(Ok(retain_named_call_evaluation_order(
                    TypedExpr {
                        expr: ExprKind::Call {
                            target: CallTarget::Intrinsic(intrinsic),
                            args: vec![receiver, divisor, scale, mode],
                        },
                        ty: result_type,
                    },
                    &plan,
                )));
            }
            _ => {
                return Some(Err(SemanticError {
                    code: "E_INTERNAL_NUMERIC_MATRIX",
                    message: "rounded numeric operands violate their typed operator matrix".into(),
                }));
            }
        };
        let folded = match folded {
            Ok(folded) => folded,
            Err(error) => {
                let error = ConstantNumericError::Numeric(error);
                return Some(Err(SemanticError {
                    code: error.code(),
                    message: error.to_string(),
                }));
            }
        };
        let value = match folded {
            ConstantNumeric::Decimal(value) => value,
            ConstantNumeric::Quantity(value) => value.into_numeric(),
            ConstantNumeric::Int(_) => unreachable!("rounded division never returns int"),
        };
        return Some(Ok(TypedExpr {
            expr: ExprKind::DecimalLiteral {
                spelling: value.to_string(),
                value,
            },
            ty: result_type,
        }));
    }
    Some(Ok(retain_named_call_evaluation_order(
        TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Intrinsic(intrinsic),
                args: vec![receiver, divisor, scale, mode],
            },
            ty: result_type,
        },
        &plan,
    )))
}
fn analyze_expr_expected(
    context: &SemanticContext,
    expr: &Expr,
    vars: &mut HashMap<String, Type>,
    expected: Option<&Type>,
) -> Result<TypedExpr, SemanticError> {
    analyze_expr_in_context(context, expr, vars, expected, false)
}
fn analyze_expr_in_context(
    context: &SemanticContext,
    expr: &Expr,
    vars: &mut HashMap<String, Type>,
    expected: Option<&Type>,
    boundary: bool,
) -> Result<TypedExpr, SemanticError> {
    // Blocks nested in expressions are analyzed all-or-nothing.
    let recovery = context.statement_recovery.replace(false);
    let result = analyze_expr_expected_inner(context, expr, vars, expected, boundary);
    context.statement_recovery.set(recovery);
    let result = result.and_then(|typed| {
        if matches!(
            typed.kind(),
            ExprKind::JsonObject(_) | ExprKind::JsonArray(_)
        ) && let Err(error) = crate::abi_schema::json_construction_schema(&typed)
        {
            return Err(SemanticError {
                code: "E_JSON_SCHEMA_LIMIT",
                message: error.to_string(),
            });
        }
        context.record_typed_hir_node(expr, &typed.ty)?;
        Ok(typed)
    });
    if result.is_err() {
        context.capture_expression_diagnostic(expr, None);
    }
    result
}
fn analyze_expr_expected_inner(
    context: &SemanticContext,
    expr: &Expr,
    vars: &mut HashMap<String, Type>,
    expected: Option<&Type>,
    boundary: bool,
) -> Result<TypedExpr, SemanticError> {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips AST and resolved-HIR provenance wrappers")
        }
        Expr::OptionSome(value) => {
            let expected_payload = match expected
                .map(|ty| resolve_struct_type_with_context(context, ty))
                .transpose()?
            {
                Some(Type::Option(payload)) => Some(*payload),
                Some(other) => {
                    return Err(SemanticError {
                        code: "E_SUM_CONTEXT_TYPE",
                        message: format!(
                            "`Option::some` cannot initialize `{}`",
                            type_name(&other)
                        ),
                    });
                }
                None => None,
            };
            let mut value = analyze_expr_expected(context, value, vars, expected_payload.as_ref())?;
            if let Some(payload) = &expected_payload {
                ensure_assignable_and_coerce(payload, &mut value)?;
            }
            let payload = resolve_struct_type(&value.ty);
            if !is_supported_sum_payload(&payload) {
                return Err(SemanticError {
                    code: "K2003",
                    message: "Option<T> V1 payloads must be durable-value types".into(),
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::OptionSome {
                    value: Box::new(value),
                },
                ty: Type::Option(Box::new(payload)),
            })
        }
        Expr::OptionNone => {
            let payload = match expected
                .map(|ty| resolve_struct_type_with_context(context, ty))
                .transpose()?
            {
                Some(Type::Option(payload)) => payload,
                Some(other) => {
                    return Err(SemanticError {
                        code: "E_SUM_CONTEXT_TYPE",
                        message: format!(
                            "`Option::none` cannot initialize `{}`",
                            type_name(&other)
                        ),
                    });
                }
                None => {
                    return Err(SemanticError {
                        code: "E_SUM_MISSING_CONTEXT",
                        message: "`Option::none` requires an exact `Option<T>` context from an annotation, return type, field, or parameter".into(),
                    });
                }
            };
            if !is_supported_sum_payload(&payload) {
                return Err(SemanticError {
                    code: "K2003",
                    message: "Option<T> V1 payloads must be durable-value types".into(),
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::OptionNone,
                ty: Type::Option(payload),
            })
        }
        Expr::ResultOk(value) => {
            let (ok, error) = match expected
                .map(|ty| resolve_struct_type_with_context(context, ty))
                .transpose()?
            {
                Some(Type::Result(ok, error)) => (ok, error),
                Some(other) => {
                    return Err(SemanticError {
                        code: "E_SUM_CONTEXT_TYPE",
                        message: format!("`Result::ok` cannot initialize `{}`", type_name(&other)),
                    });
                }
                None => {
                    return Err(SemanticError {
                        code: "E_SUM_MISSING_CONTEXT",
                        message: "`Result::ok` requires an exact `Result<T, E>` context so the inactive error type is known".into(),
                    });
                }
            };
            let mut value = analyze_expr_expected(context, value, vars, Some(&ok))?;
            ensure_assignable_and_coerce(&ok, &mut value)?;
            if !is_supported_sum_payload(&ok) || !is_supported_sum_payload(&error) {
                return Err(SemanticError {
                    code: "K2003",
                    message: "Result<T, E> V1 payloads must be durable-value types".into(),
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::ResultOk {
                    value: Box::new(value),
                },
                ty: Type::Result(ok, error),
            })
        }
        Expr::ResultErr(error) => {
            let (ok, error_ty) = match expected
                .map(|ty| resolve_struct_type_with_context(context, ty))
                .transpose()?
            {
                Some(Type::Result(ok, error_ty)) => (ok, error_ty),
                Some(other) => {
                    return Err(SemanticError {
                        code: "E_SUM_CONTEXT_TYPE",
                        message: format!("`Result::err` cannot initialize `{}`", type_name(&other)),
                    });
                }
                None => {
                    return Err(SemanticError {
                        code: "E_SUM_MISSING_CONTEXT",
                        message: "`Result::err` requires an exact `Result<T, E>` context so the inactive success type is known".into(),
                    });
                }
            };
            let mut error = analyze_expr_expected(context, error, vars, Some(&error_ty))?;
            ensure_assignable_and_coerce(&error_ty, &mut error)?;
            if !is_supported_sum_payload(&ok) || !is_supported_sum_payload(&error_ty) {
                return Err(SemanticError {
                    code: "K2003",
                    message: "Result<T, E> V1 payloads must be durable-value types".into(),
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::ResultErr {
                    error: Box::new(error),
                },
                ty: Type::Result(ok, error_ty),
            })
        }
        Expr::Propagate(value) => {
            let value = analyze_expr(context, value, vars)?;
            let function_return = context
                .current_function_name
                .borrow()
                .as_ref()
                .and_then(|name| context.function_returns.borrow().get(name).cloned())
                .unwrap_or(Type::Unit);
            let output = match (
                resolve_struct_type(&value.ty),
                resolve_struct_type(&function_return),
            ) {
                (Type::Option(payload), Type::Option(_)) => *payload,
                (Type::Result(payload, error), Type::Result(_, return_error)) => {
                    if resolve_struct_type(&error) != resolve_struct_type(&return_error) {
                        return Err(SemanticError {
                            code: "E_PROPAGATE_ERROR_TYPE",
                            message: format!(
                                "postfix `?` has error type `{}` but the enclosing function returns `{}`; implicit error conversion is not allowed",
                                type_name(&error),
                                type_name(&return_error)
                            ),
                        });
                    }
                    *payload
                }
                (Type::Option(_), other) => {
                    return Err(SemanticError {
                        code: "E_PROPAGATE_CONTEXT",
                        message: format!(
                            "postfix `?` on Option requires an Option-returning function, found `{}`",
                            type_name(&other)
                        ),
                    });
                }
                (Type::Result(_, _), other) => {
                    return Err(SemanticError {
                        code: "E_PROPAGATE_CONTEXT",
                        message: format!(
                            "postfix `?` on Result requires a Result-returning function, found `{}`",
                            type_name(&other)
                        ),
                    });
                }
                (other, _) => {
                    return Err(SemanticError {
                        code: "E_PROPAGATE_TYPE",
                        message: format!(
                            "postfix `?` expects Option or Result, found `{}`",
                            type_name(&other)
                        ),
                    });
                }
            };
            Ok(TypedExpr {
                expr: ExprKind::Propagate {
                    value: Box::new(value),
                },
                ty: output,
            })
        }
        Expr::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let condition = analyze_expr(context, condition, vars)?;
            crate::secret::reject_secret_control_flow(&condition)?;
            if condition.ty != Type::Bool {
                return Err(SemanticError {
                    code: "K2003",
                    message: "if condition must be bool".into(),
                });
            }
            let Some(else_branch) = else_branch else {
                return Err(SemanticError {
                    code: "E_IF_EXPRESSION_ELSE",
                    message: "expression-valued `if` requires an `else` block".into(),
                });
            };
            let (then_branch, else_branch, ty) =
                analyze_expression_branches(context, then_branch, else_branch, vars, expected, boundary)?;
            Ok(TypedExpr {
                expr: ExprKind::If {
                    condition: Box::new(condition),
                    then_branch,
                    else_branch,
                },
                ty,
            })
        }
        Expr::IfLet {
            pattern,
            value,
            then_branch,
            else_branch,
        } => {
            let value = analyze_expr(context, value, vars)?;
            let (pattern, binding) = analyze_sum_pattern(context, pattern, &value.ty)?;
            let Some(else_branch) = else_branch else {
                return Err(SemanticError {
                    code: "E_IF_LET_EXPRESSION_ELSE",
                    message: "expression-valued `if let` requires an `else` block".into(),
                });
            };
            let mut then_vars = vars.clone();
            if let Some((name, ty)) = binding {
                ensure_new_local_binding(context, &name, &then_vars)?;
                then_vars.insert(name, ty);
            }
            let (then_branch, else_branch, ty) = analyze_expression_branches_with_envs(
                context,
                then_branch,
                else_branch,
                &mut then_vars,
                &mut vars.clone(),
                expected,
                boundary,
            )?;
            Ok(TypedExpr {
                expr: ExprKind::IfLet {
                    pattern,
                    value: Box::new(value),
                    then_branch,
                    else_branch,
                },
                ty,
            })
        }
        Expr::Match { value, arms } => {
            let value = analyze_expr(context, value, vars)?;
            analyze_match_expression(context, value, arms, vars, expected, boundary)
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            let c = analyze_expr(context, cond, vars)?;
            crate::secret::reject_secret_control_flow(&c)?;
            if c.ty != Type::Bool {
                return Err(SemanticError {
                    code: "K2003",
                    message: "conditional expects a bool condition".into(),
                });
            }
            let mut t1 = analyze_expr_in_context(context, then_expr, vars, expected, boundary)?;
            let branch_type = if let Some(expected) = expected {
                let mut contextual = t1.clone();
                match if boundary { ensure_boundary_assignable_and_coerce(expected, &mut contextual) } else { ensure_assignable_and_coerce(expected, &mut contextual) } {
                    Ok(()) => {
                        t1 = contextual;
                        expected.clone()
                    }
                    Err(error) if error.code == "E_TYPE_ANNOTATION_MISMATCH" => t1.ty.clone(),
                    Err(error) => return Err(error),
                }
            } else {
                t1.ty.clone()
            };
            let mut t2 = analyze_expr_in_context(context, else_expr, vars, Some(&branch_type), boundary)?;
            if let Err(error) = if boundary { ensure_boundary_assignable_and_coerce(&branch_type, &mut t2) } else { ensure_assignable_and_coerce(&branch_type, &mut t2) } {
                if error.code != "E_TYPE_ANNOTATION_MISMATCH" {
                    return Err(error);
                }
                return Err(SemanticError {
                    code: "K2003",
                    message: "conditional branches must have the same type".into(),
                });
            }
            if t1.ty != t2.ty {
                return Err(SemanticError {
                    code: "K2003",
                    message: "conditional branches must have the same type".into(),
                });
            }
            Ok(TypedExpr {
                expr: ExprKind::Conditional {
                    cond: Box::new(c),
                    then_expr: Box::new(t1.clone()),
                    else_expr: Box::new(t2.clone()),
                },
                ty: t1.ty,
            })
        }
        Expr::Tuple(elems) => {
            if elems.is_empty() {
                return Ok(TypedExpr {
                    expr: ExprKind::Tuple(Vec::new()),
                    ty: Type::Unit,
                });
            }
            let expected_elements = match expected
                .map(|expected| resolve_struct_type_with_context(context, expected))
                .transpose()?
            {
                Some(Type::Tuple(elements)) if elements.len() == elems.len() => Some(elements),
                _ => None,
            };
            let mut typed = Vec::with_capacity(elems.len());
            for (index, element) in elems.iter().enumerate() {
                let expected_element = expected_elements
                    .as_ref()
                    .and_then(|elements| elements.get(index));
                let mut element = analyze_expr_expected(context, element, vars, expected_element)?;
                if let Some(expected_element) = expected_element {
                    ensure_assignable_and_coerce(expected_element, &mut element)?;
                }
                typed.push(element);
            }
            let tys = typed.iter().map(|t| t.ty.clone()).collect();
            Ok(TypedExpr {
                expr: ExprKind::Tuple(typed),
                ty: Type::Tuple(tys),
            })
        }
        Expr::List(elements) => analyze_list_literal(context, elements, vars, expected),
        Expr::ListComprehension {
            expression,
            item,
            source,
            condition,
        } => analyze_list_comprehension(
            context,
            expression,
            item,
            source,
            condition.as_deref(),
            vars,
            expected,
        ),
        Expr::JsonObject(entries) => {
            if entries.len() > 64 {
                return Err(SemanticError {
                    code: "E_JSON_CAPACITY",
                    message: format!(
                        "native JSON objects contain at most 64 entries per node; this object has {}",
                        entries.len()
                    ),
                });
            }
            let mut keys = HashSet::with_capacity(entries.len());
            let mut typed_entries = Vec::with_capacity(entries.len());
            for entry in entries {
                if !keys.insert(entry.key.clone()) {
                    return Err(SemanticError {
                        code: "E_JSON_DUPLICATE_KEY",
                        message: format!(
                            "native JSON object key `{}` is supplied more than once after string decoding",
                            entry.key
                        ),
                    });
                }
                typed_entries.push((
                    entry.key.clone(),
                    analyze_native_json_value(context, &entry.value, vars)?,
                ));
            }
            Ok(TypedExpr {
                expr: ExprKind::JsonObject(typed_entries),
                ty: Type::Json,
            })
        }
        Expr::JsonArray(elements) => {
            if elements.len() > 64 {
                return Err(SemanticError {
                    code: "E_JSON_CAPACITY",
                    message: format!(
                        "native JSON arrays contain at most 64 elements per node; this array has {}",
                        elements.len()
                    ),
                });
            }
            let elements = elements
                .iter()
                .map(|element| analyze_native_json_value(context, element, vars))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TypedExpr {
                expr: ExprKind::JsonArray(elements),
                ty: Type::Json,
            })
        }
        Expr::IntLiteral(n) => typed_int_literal(n),
        Expr::DecimalLiteral(spelling) => {
            let value = parse_decimal_literal(spelling)?;
            Ok(TypedExpr {
                expr: ExprKind::DecimalLiteral {
                    value,
                    spelling: spelling.clone(),
                },
                ty: Type::Decimal,
            })
        }
        Expr::Bool(b) => Ok(TypedExpr {
            expr: ExprKind::Bool(*b),
            ty: Type::Bool,
        }),
        Expr::String(s) => Ok(TypedExpr {
            expr: ExprKind::String(s.clone()),
            ty: Type::String,
        }),
        Expr::Bytes(bytes) => Ok(TypedExpr {
            expr: ExprKind::Bytes(bytes.clone()),
            ty: Type::Bytes,
        }),
        Expr::Ident(name) => {
            if let Some((target, binding_ty)) = context.validate_value_target(expr, name, vars)? {
                use crate::resolved::ResolvedValueTarget;
                return match target {
                    ResolvedValueTarget::Binding(_) => Ok(TypedExpr {
                        expr: ExprKind::Ident(name.clone()),
                        ty: binding_ty.expect("binding target supplies its semantic type"),
                    }),
                    ResolvedValueTarget::State(_) | ResolvedValueTarget::ExternalState => vars
                        .get(name)
                        .cloned()
                        .map(|ty| TypedExpr {
                            expr: ExprKind::Ident(name.clone()),
                            ty,
                        })
                        .ok_or_else(|| SemanticError {
                            code: "E_INTERNAL_RESOLUTION",
                            message: format!(
                                "resolved state `{name}` is absent from the typed environment"
                            ),
                        }),
                    ResolvedValueTarget::Const(_) | ResolvedValueTarget::ExternalConst => context
                        .consts
                        .borrow()
                        .get(name)
                        .cloned()
                        .ok_or_else(|| SemanticError {
                            code: "E_INTERNAL_RESOLUTION",
                            message: format!(
                                "resolved const `{name}` is absent from the typed environment"
                            ),
                        }),
                    ResolvedValueTarget::ImportedVariant => {
                        let code = context.variant_codes.borrow().get(name).copied().ok_or_else(|| SemanticError {
                            code: "E_UNKNOWN_ENUM_VARIANT", message: format!("enum variant `{name}` is not exported by the locked type graph"),
                        })?;
                        typed_variant_value(context, name, code)
                    }
                    ResolvedValueTarget::VariantCode(resolved_code) => {
                        let code = context.variant_codes.borrow().get(name).copied().ok_or_else(|| {
                            SemanticError {
                                code: "E_INTERNAL_RESOLUTION",
                                message: format!(
                                    "resolved error code `{name}` is absent from the typed environment"
                                ),
                            }
                        })?;
                        if code != resolved_code {
                            return Err(SemanticError {
                                code: "E_INTERNAL_RESOLUTION",
                                message: format!("error code `{name}` changed after resolution"),
                            });
                        }
                        typed_variant_value(context, name, code)
                    }
                    ResolvedValueTarget::Intrinsic => Err(Builtin::nominal_value(name)
                        .map_or_else(
                            || SemanticError {
                                code: "E_INTRINSIC_CONTEXT",
                                message: format!(
                                    "intrinsic value `{name}` is only valid in its declared operation context"
                                ),
                            },
                            misplaced_nominal_value,
                        )),
                };
            }
            if let Some(ty) = vars.get(name).cloned() {
                return Ok(TypedExpr {
                    expr: ExprKind::Ident(name.clone()),
                    ty,
                });
            }
            if let Some(value) = context.consts.borrow().get(name).cloned() {
                return Ok(value);
            }
            if let Some(code) = context.variant_codes.borrow().get(name).copied() {
                return typed_variant_value(context, name, code);
            }
            Err(SemanticError {
                code: "K2002",
                message: format!("undefined variable {name}"),
            })
        }
        Expr::Unary { op, expr: inner } => {
            // A quantity cannot be negated. Keep the operand in its literal
            // domain so the enclosing contextual conversion reports the
            // stable `E_NEGATIVE_QUANTITY` diagnostic for `quantity = -1`
            // instead of treating this as a runtime quantity negation.
            let unary_expected =
                expected.filter(|expected| resolve_struct_type(expected) != Type::Quantity);
            let inner_t = analyze_expr_expected(context, inner, vars, unary_expected)?;
            crate::secret::reject_secret_ordinary_operation(&[&inner_t])?;
            match op {
                UnaryOp::Neg => {
                    let Some(kind) = numeric_kind(&inner_t.ty) else {
                        return Err(SemanticError {
                            code: "K2003",
                            message: "unary '-' expects numeric".into(),
                        });
                    };
                    if !matches!(kind, NumericKind::Int | NumericKind::Decimal) {
                        return Err(SemanticError {
                            code: "E_QUANTITY_NEGATION",
                            message: "unary `-` is supported for int and decimal; quantity is non-negative"
                                .into(),
                        });
                    }
                    let typed = TypedExpr {
                        expr: ExprKind::Unary {
                            op: *op,
                            expr: Box::new(inner_t),
                        },
                        ty: numeric_kind_to_type(kind),
                    };
                    match crate::checked_arithmetic::evaluate(&typed) {
                        Ok(Some(value)) => Ok(value.into_typed_expr()),
                        Ok(None) => Ok(typed),
                        Err(error) => Err(SemanticError {
                            code: error.code(),
                            message: error.to_string(),
                        }),
                    }
                }
                UnaryOp::Not => {
                    if inner_t.ty != Type::Bool {
                        return Err(SemanticError {
                            code: "K2003",
                            message: "unary '!' expects bool".into(),
                        });
                    }
                    Ok(TypedExpr {
                        expr: ExprKind::Unary {
                            op: *op,
                            expr: Box::new(inner_t.clone()),
                        },
                        ty: Type::Bool,
                    })
                }
            }
        }
        Expr::Member { object, field } => {
            let mut obj = analyze_expr(context, object, vars)?;
            let resolved_obj_ty = resolve_struct_type_with_context(context, &obj.ty)?;
            obj.ty = resolved_obj_ty.clone();
            // Tuple numeric indexing
            if let Ok(idx) = field.parse::<usize>() {
                match &resolved_obj_ty {
                    Type::Tuple(ts) => {
                        if let Some(t) = ts.get(idx) {
                            return Ok(TypedExpr {
                                expr: ExprKind::Member {
                                    object: Box::new(obj),
                                    field: field.clone(),
                                },
                                ty: resolve_struct_type(t),
                            });
                        } else {
                            return Err(SemanticError {
                                code: "E_TUPLE_INDEX",
                                message: format!(
                                    "tuple index {} out of bounds (len={})",
                                    idx,
                                    ts.len()
                                ),
                            });
                        }
                    }
                    Type::Struct { name, .. } => {
                        return Err(SemanticError {
                            code: "K2002",
                            message: format!(
                                "tuple index on non-tuple type struct {name}; unknown field '{field}' on struct {name}"
                            ),
                        });
                    }
                    other => {
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!("tuple index on non-tuple type {}", type_name(other)),
                        });
                    }
                }
            }
            // Named access on a tuple is invalid
            if matches!(&resolved_obj_ty, Type::Tuple(_)) {
                return Err(SemanticError {
                    code: "K2002",
                    message: format!("unknown field '{field}' on tuple"),
                });
            }
            // Struct named field: map to numeric index for lowering
            if let Type::Struct { name, fields } = &resolved_obj_ty {
                if let Some((idx, (_fname, fty))) = fields
                    .iter()
                    .enumerate()
                    .find(|(_, (fname, _))| fname == field)
                {
                    return Ok(TypedExpr {
                        expr: ExprKind::Member {
                            object: Box::new(obj),
                            field: idx.to_string(),
                        },
                        ty: resolve_struct_type(fty),
                    });
                } else {
                    let avail: Vec<&str> = fields.iter().map(|(f, _)| f.as_str()).collect();
                    context.capture_help(
                        context.expression_source(expr),
                        type_help::unknown_field_help(name, field, &avail),
                    );
                    return Err(SemanticError {
                        code: "K2002",
                        message: format!(
                            "unknown field '{field}' on struct {name} (available: {})",
                            avail.join(", ")
                        ),
                    });
                }
            }
            // Attempt to resolve to a flattened bound variable like `base#i#j` for nested structs.
            let try_flatten = || -> Option<(String, Type)> {
                fn collect_path(e: &TypedExpr, out: &mut Vec<usize>) -> Option<String> {
                    match e.kind() {
                        ExprKind::Member { object, field } => {
                            let base = collect_path(object, out)?;
                            let i = field.parse::<usize>().ok()?;
                            out.push(i);
                            Some(base)
                        }
                        ExprKind::Ident(nm) => Some(nm.clone()),
                        _ => None,
                    }
                }
                let mut path = Vec::new();
                let base = collect_path(
                    &TypedExpr {
                        expr: ExprKind::Member {
                            object: Box::new(obj.clone()),
                            field: field.clone(),
                        },
                        ty: Type::Int,
                    },
                    &mut path,
                )?;
                if path.is_empty() {
                    return None;
                }
                let mut name = base;
                for i in path.into_iter().rev() {
                    name.push('#');
                    name.push_str(&i.to_string());
                }
                // Look up type from vars
                if let Some(ty) = vars.get(&name).cloned() {
                    return Some((name, ty));
                }
                None
            };
            if let Some((n, ty)) = try_flatten() {
                return Ok(TypedExpr {
                    expr: ExprKind::Ident(n),
                    ty,
                });
            }
            Err(SemanticError {
                code: "K2002",
                message: format!("unknown field '{field}' on type {}", type_name(&obj.ty)),
            })
        }
        Expr::Index { target, index } => {
            let tgt = analyze_expr(context, target, vars)?;
            let mut idx = analyze_expr(context, index, vars)?;
            crate::secret::reject_secret_key(&idx)?;
            match tgt.ty.clone() {
                Type::List(element, _) => {
                    let expected_option = expected
                        .map(|ty| resolve_struct_type_with_context(context, ty))
                        .transpose()?
                        .is_some_and(|expected| {
                            matches!(expected, Type::Option(expected) if *expected == *element)
                        });
                    let fix = if expected_option && resolve_struct_type(&idx.ty) == Type::Int {
                        match (
                            context.expression_source(target),
                            context.expression_source(index),
                        ) {
                            (Some(target), Some(index)) => {
                                Some(crate::semantic_diagnostics::SemanticFix::ListGet {
                                    target,
                                    index,
                                })
                            }
                            _ => None,
                        }
                    } else {
                        None
                    };
                    context.capture_expression_diagnostic(expr, fix);
                    Err(SemanticError {
                        code: "E_LIST_UNSAFE_INDEX",
                        message: "unchecked List indexing is not part of Kotodama V1; use `list.get(index)` and handle `Option<T>`"
                            .into(),
                    })
                }
                Type::StateMap(k, _) => {
                    ensure_assignable_and_coerce(&k, &mut idx)?;
                    ensure_in_memory_map_word_types(context, &tgt)?;
                    Err(SemanticError {
                        code: "E_STATE_MAP_OPTIONAL_READ",
                        message: "StateMap rvalue indexing cannot represent an absent key; use `map.get(key)` and handle Option<V>"
                            .into(),
                    })
                }
                _ => Err(SemanticError {
                    code: "K2003",
                    message: "indexing not supported on this type".into(),
                }),
            }
        }
        Expr::Binary { op, left, right } => {
            let mut left_t = analyze_expr(context, left, vars)?;
            let mut right_t = analyze_expr(context, right, vars)?;
            crate::secret::reject_secret_ordinary_operation(&[&left_t, &right_t])?;
            if *op == BinaryOp::Mod
                && (resolve_struct_type(&left_t.ty) == Type::Quantity
                    || resolve_struct_type(&right_t.ty) == Type::Quantity
                    || expected
                        .is_some_and(|expected| resolve_struct_type(expected) == Type::Quantity))
            {
                return Err(SemanticError {
                    code: "E_QUANTITY_REMAINDER",
                    message: "quantity does not support `%`; divide with an explicit rounding mode, for example `value.div_round(divisor: d, scale: 6, mode: Rounding::floor)`"
                        .into(),
                });
            }
            coerce_contextual_numeric_literals(*op, expected, &mut left_t, &mut right_t)?;
            use BinaryOp::*;
            match op {
                Add | Sub | Mul | Div | Mod => {
                    reject_implicit_int_decimal_mix(&left_t.ty, &right_t.ty)?;
                    let Some(result_ty) = arithmetic_result_type(*op, &left_t.ty, &right_t.ty)
                    else {
                        context.capture_help(
                            context.expression_source(expr),
                            type_help::operator_help(*op, &left_t.ty, &right_t.ty),
                        );
                        return Err(SemanticError {
                            code: "K2003",
                            message: type_help::operator_message(
                                type_help::binary_symbol(*op),
                                &left_t.ty,
                                &right_t.ty,
                            ),
                        });
                    };
                    let typed = TypedExpr {
                        expr: ExprKind::Binary {
                            op: *op,
                            left: Box::new(left_t),
                            right: Box::new(right_t),
                        },
                        ty: result_ty,
                    };
                    match crate::checked_arithmetic::evaluate(&typed) {
                        Ok(Some(value)) => Ok(value.into_typed_expr()),
                        Ok(None) => Ok(typed),
                        Err(error) => Err(SemanticError {
                            code: error.code(),
                            message: error.to_string(),
                        }),
                    }
                }
                And | Or => {
                    if left_t.ty != Type::Bool || right_t.ty != Type::Bool {
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "`{}` expects `bool` operands, found {} and {}",
                                type_help::binary_symbol(*op),
                                type_help::quoted(&left_t.ty),
                                type_help::quoted(&right_t.ty),
                            ),
                        });
                    }
                    Ok(TypedExpr {
                        expr: ExprKind::Binary {
                            op: *op,
                            left: Box::new(left_t),
                            right: Box::new(right_t),
                        },
                        ty: Type::Bool,
                    })
                }
                Eq | Ne => {
                    reject_implicit_int_decimal_mix(&left_t.ty, &right_t.ty)?;
                    let numeric_result = numeric_result_type(&left_t.ty, &right_t.ty);
                    let numeric_ok = numeric_result.is_some();
                    if left_t.ty != right_t.ty
                        && !(is_blob_like(&left_t.ty) && is_blob_like(&right_t.ty))
                        && !numeric_ok
                    {
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "`{}` compares values of one type, found {} and {}",
                                type_help::binary_symbol(*op),
                                type_help::quoted(&left_t.ty),
                                type_help::quoted(&right_t.ty),
                            ),
                        });
                    }
                    if !is_eq_comparable_type(&left_t.ty) {
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "equality is not supported for type {}",
                                type_name(&left_t.ty)
                            ),
                        });
                    }
                    Ok(TypedExpr {
                        expr: ExprKind::Binary {
                            op: *op,
                            left: Box::new(left_t),
                            right: Box::new(right_t),
                        },
                        ty: Type::Bool,
                    })
                }
                Lt | Le | Gt | Ge => {
                    reject_implicit_int_decimal_mix(&left_t.ty, &right_t.ty)?;
                    let Some(_result_ty) = numeric_result_type(&left_t.ty, &right_t.ty) else {
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "comparison `{}` is not defined for {} and {}",
                                type_help::binary_symbol(*op),
                                type_help::quoted(&left_t.ty),
                                type_help::quoted(&right_t.ty),
                            ),
                        });
                    };
                    Ok(TypedExpr {
                        expr: ExprKind::Binary {
                            op: *op,
                            left: Box::new(left_t),
                            right: Box::new(right_t),
                        },
                        ty: Type::Bool,
                    })
                }
            }
        }
        Expr::StructLiteral { .. } => analyze_record_literal(context, expr, vars, false),
        Expr::ArgumentRecord { .. } => Err(SemanticError { code: "E_TEST_ARGUMENT_RECORD", message: "typed argument records are accepted only as the arguments of a test invocation helper".into() }),
        Expr::Call {
            name,
            args,
            argument_names,
            implicit_receiver,
        } => {
            if context.event_names.borrow().contains(name) {
                return Err(SemanticError {
                    code: "E_EVENT_VALUE",
                    message: format!(
                        "event `{name}` can only be emitted with `emit {name} {{ ... }};`"
                    ),
                });
            }
            if let Some(result) = analyze_contract_call(context, name, args, argument_names.as_deref(), *implicit_receiver, vars) {
                context.validate_call_target(expr, name, name, *implicit_receiver)?;
                return result;
            }
            let source_name = name.clone();
            let user_parameters = context.function_params.borrow().get(&source_name).cloned();
            let mut user_receiver = None;
            if *implicit_receiver
                && let Some(parameter) = user_parameters.as_ref().and_then(|params| params.first())
                && let Some(receiver) = args.first()
                && context.function_modifiers.borrow().get(&source_name)
                    .is_none_or(|modifiers| modifiers.kind == FunctionKind::Private)
                && let Ok(mut typed) = analyze_expr(context, receiver, vars)
                && user_receiver_accepts(&parameter.ty, &typed.ty)
            {
                ensure_boundary_assignable_and_coerce(&parameter.ty, &mut typed)?;
                user_receiver = Some(typed);
            }
            let is_user_call = user_parameters.is_some()
                && (!*implicit_receiver || user_receiver.is_some());
            let source_builtin = if is_user_call {
                None
            } else if *implicit_receiver {
                Builtin::from_name(&source_name).filter(|builtin| {
                    matches!(
                        builtin.surface(),
                        BuiltinSurface::MethodOnly | BuiltinSurface::FunctionOrMethod
                    )
                })
            } else {
                Builtin::from_source_name(&source_name)
            };
            if !is_user_call
                && !*implicit_receiver
                && source_builtin.is_none()
                && let Some(message) = crate::parser::removed_free_helper_message(&source_name)
            {
                return Err(SemanticError {
                    code: "K2002",
                    message: message.to_owned(),
                });
            }
            if !is_user_call
                && !*implicit_receiver
                && source_builtin.is_none()
                && let Some(builtin) = Builtin::from_name(&source_name)
            {
                if builtin.mode() == BuiltinMode::CompilerInternal {
                    validate_builtin_mode(context, builtin)?;
                }
                return Err(SemanticError {
                    code: "E_NON_CANONICAL_BUILTIN",
                    message: format!(
                        "legacy or non-canonical builtin spelling `{source_name}` is not supported; use `{}`",
                        builtin.source_name()
                    ),
                });
            }
            let name = if is_user_call {
                source_name.clone()
            } else if *implicit_receiver {
                match name.as_str() {
                    "ok_or" => OPTION_OK_OR_INTRINSIC.to_owned(),
                    "or_err" => RESULT_OR_ERR_INTRINSIC.to_owned(),
                    _ => normalize_namespaced(name),
                }
            } else {
                normalize_namespaced(name)
            };
            context.validate_call_target(expr, &source_name, &name, *implicit_receiver)?;
            if !is_user_call {
            if let Some(result) = analyze_state_page_call(
                context,
                &name,
                args,
                argument_names.as_deref(),
                *implicit_receiver,
                vars,
            ) {
                return result;
            }
            if let Some(result) = analyze_list_method_call(
                context,
                &name,
                args,
                argument_names.as_deref(),
                *implicit_receiver,
                vars,
            ) {
                return result;
            }
            if let Some(result) = analyze_decimal_to_int_round_call(
                context,
                &name,
                args,
                argument_names.as_deref(),
                *implicit_receiver,
                vars,
            ) {
                return result;
            }
            if let Some(result) = analyze_numeric_mul_div_method_call(
                context,
                &name,
                args,
                argument_names.as_deref(),
                *implicit_receiver,
                vars,
            ) {
                return result;
            }
            if let Some(result) = analyze_numeric_round_method_call(
                context,
                &name,
                args,
                argument_names.as_deref(),
                *implicit_receiver,
                vars,
            ) {
                return result;
            }
            }
            if context.structs.borrow().contains_key(&name) {
                let fields = context
                    .structs
                    .borrow()
                    .get(&name)
                    .map(|fields| {
                        fields
                            .iter()
                            .map(|(field, _)| field.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let field_names = fields.join(", ");
                let arguments = args
                    .iter()
                    .map(|argument| context.expression_source(argument))
                    .collect::<Option<Vec<_>>>();
                let fix = arguments.map(|arguments| {
                    crate::semantic_diagnostics::SemanticFix::PositionalStruct {
                        name: source_name.clone(),
                        fields,
                        arguments,
                    }
                });
                context.capture_expression_diagnostic(expr, fix);
                return Err(SemanticError {
                    code: "E_POSITIONAL_STRUCT",
                    message: format!(
                        "positional construction `{source_name}(...)` is retired; use `{source_name} {{ {field_names} }}` with named fields"
                    ),
                });
            }
            let mut argument_plan = CallArgumentPlan {
                ordered: args.clone(),
                evaluation_order: (0..args.len()).collect(),
                is_named: false,
            };
            if let Some(builtin) = source_builtin {
                let canonical_function_call = source_name == builtin.source_name()
                    && matches!(
                        builtin.surface(),
                        BuiltinSurface::Function | BuiltinSurface::FunctionOrMethod
                    );
                let canonical_method_call = *implicit_receiver
                    && source_name == builtin.name()
                    && matches!(
                        builtin.surface(),
                        BuiltinSurface::MethodOnly | BuiltinSurface::FunctionOrMethod
                    );
                if builtin.mode() != BuiltinMode::CompilerInternal
                    && !canonical_function_call
                    && !canonical_method_call
                {
                    return Err(SemanticError {
                        code: "E_NON_CANONICAL_BUILTIN",
                        message: format!(
                            "legacy or non-canonical builtin spelling `{source_name}` is not supported; use `{}`",
                            builtin.source_name()
                        ),
                    });
                }
                validate_builtin_mode(context, builtin)?;
                if builtin == Builtin::VrfVerify
                    && (args.len() != 1
                        || argument_names.as_deref().is_some_and(|names| {
                            !names.iter().map(Option::as_deref).eq([Some("request")])
                        }))
                {
                    return Err(SemanticError {
                        code: "E_RETIRED_VRF_VERIFY_ARGS",
                        message: "the four-register VRF verify form is retired; pass one bytes-encoded VrfVerifyRequest as `request`".into(),
                    });
                }
                let signature = builtin.signature();
                let receiver_count = usize::from(*implicit_receiver);
                let parameter_names = signature
                    .parameter_names
                    .get(receiver_count..)
                    .unwrap_or_default()
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>();
                let required = signature
                    .parameters
                    .get(receiver_count..)
                    .unwrap_or_default()
                    .iter()
                    .map(|parameter| !parameter.ends_with('?'))
                    .collect::<Vec<_>>();
                argument_plan = reorder_builtin_call_arguments(
                    builtin,
                    &source_name,
                    args,
                    argument_names.as_deref(),
                    *implicit_receiver,
                    &parameter_names,
                    &required,
                )
                .inspect_err(|error| {
                    if error.code == "E_NAMED_ARGUMENTS_REQUIRED" && !*implicit_receiver {
                        let fix = labelled_builtin_call_fix(
                            &source_name,
                            args,
                            argument_names.as_deref(),
                            &parameter_names,
                        );
                        let example = fix.clone().unwrap_or_else(|| {
                            format!(
                                "{source_name}({})",
                                parameter_names
                                    .iter()
                                    .map(|name| format!("{name}: ..."))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        });
                        if let Some(primary) = context.expression_source(expr) {
                            context.capture_structured(
                                crate::semantic_diagnostics::SemanticDiagnostic::at(
                                    primary,
                                    fix.map(|replacement| {
                                        crate::semantic_diagnostics::SemanticFix::Replace {
                                            replacement,
                                        }
                                    }),
                                )
                                .with_help(format!(
                                    "`{source_name}` takes labelled arguments: `{example}`. A variable spelled exactly like a label may be passed bare."
                                )),
                            );
                        }
                    }
                    capture_named_argument_help(
                        context,
                        expr,
                        error,
                        &source_name,
                        argument_names.as_deref(),
                        args.len().saturating_sub(usize::from(*implicit_receiver)),
                        &parameter_names,
                    );
                })?;
            } else if is_user_call
                && let Some(signature) = context.function_params.borrow().get(&name).cloned()
            {
                let receiver_count = usize::from(*implicit_receiver);
                if argument_names
                    .as_ref()
                    .is_some_and(|names| names.len() != args.len().saturating_sub(receiver_count))
                {
                    return Err(SemanticError {
                        code: "E_MALFORMED_CALL",
                        message: format!(
                            "call `{source_name}` has inconsistent source argument metadata"
                        ),
                    });
                }
                let user_signature = signature.get(receiver_count..).unwrap_or_default();
                let parameter_names = user_signature
                    .iter()
                    .map(|parameter| parameter.name.clone())
                    .collect::<Vec<_>>();
                let required = vec![true; parameter_names.len()];
                let positional_prefix = user_signature
                    .iter()
                    .take_while(|parameter| parameter.call_mode == ParameterCallMode::Positional)
                    .count();
                // Ordinary function parameters accept either a positional value or
                // their declared label. Normalize only unlabeled non-`_` arguments
                // before using the same duplicate, arity and evaluation-order checks.
                let first_named = argument_names
                    .as_ref()
                    .and_then(|names| names.iter().position(Option::is_some))
                    .unwrap_or(usize::MAX);
                let optional_labels = (0..args.len().saturating_sub(receiver_count))
                    .map(|index| {
                        argument_names
                            .as_ref()
                            .and_then(|names| names[index].clone())
                            .or_else(|| {
                                (index >= positional_prefix && index < first_named)
                                    .then(|| parameter_names.get(index).cloned())
                                    .flatten()
                            })
                    })
                    .collect::<Vec<_>>();
                argument_plan = reorder_call_arguments(
                    &source_name,
                    args,
                    Some(&optional_labels),
                    *implicit_receiver,
                    &parameter_names,
                    &required,
                    positional_prefix,
                )
                .inspect_err(|error| {
                    capture_named_argument_help(
                        context,
                        expr,
                        error,
                        &source_name,
                        Some(&optional_labels),
                        optional_labels.len(),
                        &parameter_names,
                    );
                })?;
                argument_plan.is_named = first_named != usize::MAX;
            } else if argument_names.is_some() {
                let intrinsic_names: &[&str] = match name.as_str() {
                    "option::some"
                    | "result::ok"
                    | "decimal::from_int"
                    | "decimal::to_int_exact"
                    | "decimal::to_int_trunc"
                    | "quantity::try_from_int"
                    | "quantity::try_from_decimal"
                    | "decimal::from_quantity" => &["value"],
                    "result::err" => &["error"],
                    "unwrap_or" | "unwrap_err_or" => &["default"],
                    "expect" | OPTION_OK_OR_INTRINSIC | RESULT_OR_ERR_INTRINSIC => &["error"],
                    _ => &[],
                };
                if !intrinsic_names.is_empty() {
                    let parameter_names = intrinsic_names
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect::<Vec<_>>();
                    argument_plan = reorder_flexible_call_arguments(
                        &source_name,
                        args,
                        argument_names.as_deref(),
                        *implicit_receiver,
                        &parameter_names,
                        &vec![true; parameter_names.len()],
                    )?;
                }
            }
            let args = argument_plan.ordered.as_slice();
            if matches!(
                source_builtin,
                Some(Builtin::PointerConstructor(PointerConstructor::Json))
            ) && args.len() == 1
                && !matches!(args[0].kind(), Expr::String(_))
            {
                return Err(SemanticError {
                    code: "E_JSON_LITERAL_REQUIRED",
                    message: JSON_LITERAL_REQUIRED_MESSAGE.into(),
                });
            }
            if !is_user_call && name == "invoke_entrypoint" {
                return canonicalize_builtin_result(
                    Builtin::TestInvokeEntrypoint,
                    analyze_invoke_entrypoint_call(context, args, vars),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan))
                .and_then(|typed| append_test_call_site(context, expr, typed));
            }
            if !is_user_call && name == "invoke_entrypoint_as" {
                return canonicalize_builtin_result(
                    Builtin::TestInvokeEntrypointAs,
                    analyze_invoke_entrypoint_as_call(context, args, vars),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan))
                .and_then(|typed| append_test_call_site(context, expr, typed));
            }
            if !is_user_call && name == "expect_reject_as" {
                return canonicalize_builtin_result(
                    Builtin::TestExpectRejectAs,
                    analyze_expect_reject_as_call(context, args, vars),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan))
                .and_then(|typed| append_test_call_site(context, expr, typed));
            }
            if !is_user_call && name == "expect_any_reject_as" {
                return canonicalize_builtin_result(
                    Builtin::TestExpectAnyRejectAs,
                    analyze_rejection_expectation_call(context, args, vars, true),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan))
                .and_then(|typed| append_test_call_site(context, expr, typed));
            }
            if !is_user_call && name == "actor_account" {
                return canonicalize_builtin_result(
                    Builtin::TestActorAccount,
                    analyze_actor_account_call(context, args),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan))
                .and_then(|typed| append_test_call_site(context, expr, typed));
            }
            if !is_user_call && name == "actor_public_key" {
                return canonicalize_builtin_result(
                    Builtin::TestActorPublicKey,
                    analyze_actor_public_key_call(context, args),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan))
                .and_then(|typed| append_test_call_site(context, expr, typed));
            }
            if !is_user_call && name == "actor_sign" {
                return canonicalize_builtin_result(
                    Builtin::TestActorSign,
                    analyze_actor_sign_call(context, args, vars),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan))
                .and_then(|typed| append_test_call_site(context, expr, typed));
            }
            if !is_user_call && matches!(name.as_str(), "assert" | "assert_eq") {
                let builtin = if name == "assert" {
                    Builtin::Assert
                } else {
                    Builtin::AssertEq
                };
                return canonicalize_builtin_result(
                    builtin,
                    analyze_test_assertion_call(context, expr, builtin, &argument_plan, vars),
                );
            }
            // analyze builtin calls
            let mut typed_slots = (0..args.len()).map(|_| None).collect::<Vec<_>>();
            if let Some(receiver) = user_receiver {
                typed_slots[0] = Some(receiver);
            }
            let expected_parameters = if is_user_call {
                context.function_params.borrow().get(&name).cloned()
            } else {
                None
            };
            for index in argument_plan.evaluation_order.iter().copied() {
                if typed_slots[index].is_some() {
                    continue;
                }
                let argument = &args[index];
                // The batch's one list literal has an exact tuple context before
                // item analysis, so unsuffixed numeric literals become quantities.
                // Saved lists retain their declared element type and capacity.
                let batch_literal_context = if source_builtin == Some(Builtin::TransferBatch)
                    && let Expr::List(elements) = argument.kind()
                {
                    let capacity = u8::try_from(elements.len().max(1))
                        .ok()
                        .filter(|capacity| *capacity <= 64)
                        .ok_or_else(|| SemanticError {
                            code: "E_LIST_CAPACITY",
                            message: "transfer_batch list capacity exceeds 64".into(),
                        })?;
                    Some(Type::List(
                        Box::new(transfer_batch_element_type()),
                        capacity,
                    ))
                } else {
                    None
                };
                let bridge_receiver_context =
                    if index == 0 && *implicit_receiver && name == OPTION_OK_OR_INTRINSIC {
                        expected.and_then(|ty| match resolve_struct_type(ty) {
                            Type::Result(value, _) => Some(Type::Option(value)),
                            _ => None,
                        })
                    } else {
                        None
                    };
                let expected = bridge_receiver_context
                    .as_ref()
                    .or(batch_literal_context.as_ref())
                    .or_else(|| {
                        expected_parameters
                            .as_ref()
                            .and_then(|parameters| parameters.get(index))
                            .map(|parameter| &parameter.ty)
                    });
                if let Some(builtin) = source_builtin
                    && let Some(typed) =
                        analyze_builtin_literal_argument(context, builtin, index, argument)?
                {
                    typed_slots[index] = Some(typed);
                    continue;
                }
                typed_slots[index] =
                    Some(analyze_expr_in_context(context, argument, vars, expected, is_user_call)?);
            }
            let mut arg_typed = typed_slots
                .into_iter()
                .enumerate()
                .map(|(index, argument)| {
                    argument.ok_or_else(|| SemanticError {
                        code: "E_MALFORMED_CALL",
                        message: format!(
                            "call `{source_name}` did not analyze argument slot {index}"
                        ),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !is_user_call
                && let Some(result) = explicit_numeric_conversion(&name, arg_typed.clone())
            {
                return result
                    .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan));
            }
            if !is_user_call
                && let Some(result) = analyze_sum_type_call(context, &name, arg_typed.clone())
            {
                return result
                    .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan));
            }
            if let Some(builtin) = source_builtin {
                let argument_types = arg_typed
                    .iter()
                    .map(|argument| argument.ty.clone())
                    .collect::<Vec<_>>();
                return canonicalize_builtin_result(
                    builtin,
                    analyze_surface_builtin_call(context, builtin, arg_typed, expected)
                        .inspect_err(|error| {
                            capture_builtin_argument_help(
                                context,
                                builtin,
                                error,
                                args,
                                &argument_types,
                            );
                        }),
                )
                .map(|typed| retain_named_call_evaluation_order(typed, &argument_plan));
            }
            match name.as_str() {
                "Map::new" => {
                    Err(SemanticError {
                        code: "K2005",
                        message: "ephemeral maps are not part of Kotodama V1; declare durable `StateMap<K, V>` state instead".into(),
                    })
                }
                _ => {
                    let local_runtime_entrypoint = context
                        .function_modifiers
                        .borrow()
                        .get(&name)
                        .is_some_and(|modifiers| modifiers.kind != FunctionKind::Private);
                    let external_runtime_entrypoint = context
                        .external_functions
                        .borrow()
                        .get(&name)
                        .is_some_and(|signature| {
                            function_is_runtime_entrypoint(&signature.modifiers)
                        });
                    if local_runtime_entrypoint || external_runtime_entrypoint {
                        return Err(runtime_function_call_error(context, expr, &name));
                    }
                    let Some(signature) =
                        context.function_params.borrow().get(&name).cloned()
                    else {
                        if *implicit_receiver
                            && let Some(receiver) = arg_typed.first()
                            && matches!(resolve_struct_type(&receiver.ty), Type::StateMap(..))
                        {
                            context.capture_help(
                                context.expression_source(expr),
                                unknown_state_map_method_help(&source_name),
                            );
                            return Err(SemanticError {
                                code: "K2002",
                                message: format!("`StateMap` has no method `{source_name}`"),
                            });
                        }
                        return Err(SemanticError {
                            code: "K2002",
                            message: format!("unknown function or builtin `{source_name}`"),
                        });
                    };
                    if signature.len() != arg_typed.len() {
                        return Err(SemanticError {
                            code: "K2003",
                            message: format!(
                                "function `{name}` expects {} arguments, got {}",
                                signature.len(),
                                arg_typed.len()
                            ),
                        });
                    }
                    for (index, (arg, param)) in
                        arg_typed.iter_mut().zip(signature.iter()).enumerate()
                    {
                        if param.is_state {
                            if !is_state_handle_expr(context, arg) {
                                return Err(SemanticError {
                                    code: "K2005",
                                    message: format!(
                                        "state parameter `{}` requires a durable state handle argument",
                                        param.name
                                    ),
                                });
                            }
                        } else if is_state_map_expr(context, arg) {
                            return Err(SemanticError {
                                code: "E_STATE_MAP_ALIAS",
                                message:
                                    "state maps cannot be passed to user-defined functions; access declared state directly."
                                        .into(),
                            });
                        }
                        if let Err(mut error) = ensure_boundary_assignable_and_coerce(&param.ty, arg) {
                            if error.code == "E_TYPE_ANNOTATION_MISMATCH" {
                                error.code = "K2003";
                                error.message = format!(
                                    "argument `{}` of `{source_name}`: {}",
                                    param.name, error.message
                                );
                                context.capture_help(
                                    args.get(index)
                                        .and_then(|argument| context.expression_source(argument)),
                                    format!(
                                        "`{source_name}` declares `{} {}`; pass a value of that type or convert it explicitly.",
                                        render_type_name(&param.ty),
                                        param.name
                                    ),
                                );
                            }
                            return Err(error);
                        }
                    }
                    let ret_ty = context
                        .function_returns
                        .borrow()
                        .get(&name)
                        .cloned()
                        .expect("declared function parameters and returns are collected together");
                    Ok(retain_named_call_evaluation_order(TypedExpr {
                        expr: ExprKind::Call {
                            target: CallTarget::User(name.clone()),
                            args: arg_typed,
                        },
                        ty: ret_ty,
                    }, &argument_plan))
                }
            }
        }
    }
}
fn analyze_sum_type_call(
    context: &SemanticContext,
    name: &str,
    mut args: Vec<TypedExpr>,
) -> Option<Result<TypedExpr, SemanticError>> {
    let call = |intrinsic: CompilerIntrinsic, args: Vec<TypedExpr>, ty: Type| {
        Ok(TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Intrinsic(intrinsic),
                args,
            },
            ty,
        })
    };
    let error = |message: &str| {
        Err(SemanticError {
            code: "K2003",
            message: message.to_owned(),
        })
    };
    Some(match name {
        STATE_MAP_GET_INTRINSIC => {
            if args.len() != 2 {
                return Some(error("StateMap.get expects exactly one key argument"));
            }
            if !typed_map_expr_is_state(context, &args[0]) {
                return Some(error(
                    "StateMap.get is available only on declared durable state maps",
                ));
            }
            let Type::StateMap(key, value) = resolve_struct_type(&args[0].ty) else {
                return Some(error("StateMap.get receiver must be StateMap<K, V>"));
            };
            debug_assert!(is_supported_durable_value_type(&value));
            if let Err(err) = ensure_assignable_and_coerce(&key, &mut args[1]) {
                return Some(Err(err));
            }
            call(CompilerIntrinsic::StateMapGet, args, Type::Option(value))
        }
        "option::some" | "option::none" | "result::ok" | "result::err" => Err(SemanticError {
            code: "E_LEGACY_SUM_CONSTRUCTOR",
            message: "lowercase placeholder-based sum constructors are retired; use active-only `Option::some`, contextual `Option::none`, `Result::ok`, or `Result::err`".to_owned(),
        }),
        "is_some" | "is_none" => {
            if args.len() != 1 || !matches!(resolve_struct_type(&args[0].ty), Type::Option(_)) {
                return Some(error(&format!("{name} expects Option<T>")));
            }
            call(if name == "is_some" { CompilerIntrinsic::IsSome } else { CompilerIntrinsic::IsNone }, args, Type::Bool)
        }
        "is_ok" | "is_err" => {
            if args.len() != 1 || !matches!(resolve_struct_type(&args[0].ty), Type::Result(_, _)) {
                return Some(error(&format!("{name} expects Result<T, E>")));
            }
            call(if name == "is_ok" { CompilerIntrinsic::IsOk } else { CompilerIntrinsic::IsErr }, args, Type::Bool)
        }
        "unwrap_or" => {
            if args.len() != 2 {
                return Some(error("unwrap_or expects (Option<T>|Result<T, E>, T)"));
            }
            let value_ty = match resolve_struct_type(&args[0].ty) {
                Type::Option(value) | Type::Result(value, _) => *value,
                _ => {
                    return Some(error(
                        "unwrap_or receiver must be Option<T> or Result<T, E>",
                    ));
                }
            };
            if let Err(err) = ensure_assignable_and_coerce(&value_ty, &mut args[1]) {
                return Some(Err(err));
            }
            call(CompilerIntrinsic::UnwrapOr, args, value_ty)
        }
        "unwrap_err_or" => {
            if args.len() != 2 {
                return Some(error("unwrap_err_or expects (Result<T, E>, E)"));
            }
            let Type::Result(_, error_ty) = resolve_struct_type(&args[0].ty) else {
                return Some(error("unwrap_err_or receiver must be Result<T, E>"));
            };
            if let Err(err) = ensure_assignable_and_coerce(&error_ty, &mut args[1]) {
                return Some(Err(err));
            }
            call(CompilerIntrinsic::UnwrapErrOr, args, *error_ty)
        }
        "expect" | OPTION_OK_OR_INTRINSIC | RESULT_OR_ERR_INTRINSIC => {
            let intrinsic = match name {
                OPTION_OK_OR_INTRINSIC => CompilerIntrinsic::OptionOkOr,
                RESULT_OR_ERR_INTRINSIC => CompilerIntrinsic::ResultOrErr,
                _ => CompilerIntrinsic::Expect,
            };
            let method = match name {
                OPTION_OK_OR_INTRINSIC => "ok_or",
                RESULT_OR_ERR_INTRINSIC => "or_err",
                _ => name,
            };
            if args.len() != 2 {
                return Some(error(&format!("{method} expects one nominal error argument")));
            }
            let value_ty = match (method, resolve_struct_type(&args[0].ty)) {
                ("expect" | "ok_or", Type::Option(value))
                | ("expect" | "or_err", Type::Result(value, _)) => value,
                ("ok_or", _) => return Some(error("ok_or receiver must be Option<T>")),
                ("or_err", _) => return Some(error("or_err receiver must be Result<T, E>")),
                _ => return Some(error("expect receiver must be Option<T> or Result<T, E>")),
            };
            if !matches!(resolve_struct_type(&args[1].ty), Type::ErrorEnum(_)) {
                return Some(error(&format!("{method} requires a nominal error enum value")));
            }
            if name == "expect" {
                call(intrinsic, args, *value_ty)
            } else {
                let error_ty = args[1].ty.clone();
                call(intrinsic, args, Type::Result(value_ty, Box::new(error_ty)))
            }
        }
        _ => return None,
    })
}
fn is_supported_sum_payload(ty: &Type) -> bool {
    is_supported_durable_value_type(ty)
}
fn parse_declared_type(
    context: &SemanticContext,
    ty: &Option<TypeExpr>,
) -> Result<Option<Type>, SemanticError> {
    let Some(t) = ty else { return Ok(None) };
    let ty = resolve_struct_type_with_context(context, &convert_type_expr(context, t)?)
        .inspect_err(|_| context.capture_diagnostic(context.type_source(t), None))?;

    Ok(Some(ty))
}
fn analyze_const_expr(
    context: &SemanticContext,
    expr: &Expr,
    consts: &IndexMap<String, TypedExpr>,
    expected: Option<&Type>,
) -> Result<TypedExpr, SemanticError> {
    let result = analyze_const_expr_inner(context, expr, consts, expected).and_then(|typed| {
        context.record_typed_hir_node(expr, &typed.ty)?;
        Ok(typed)
    });
    if result.is_err() {
        context.capture_expression_diagnostic(expr, None);
    }
    result
}
fn analyze_const_expr_inner(
    context: &SemanticContext,
    expr: &Expr,
    consts: &IndexMap<String, TypedExpr>,
    expected: Option<&Type>,
) -> Result<TypedExpr, SemanticError> {
    match expr.kind() {
        Expr::Source { .. } | Expr::Resolved { .. } => {
            unreachable!("kind() strips AST and resolved-HIR provenance wrappers")
        }
        Expr::IntLiteral(n) => typed_int_literal(n),
        Expr::DecimalLiteral(spelling) => {
            let value = parse_decimal_literal(spelling)?;
            Ok(TypedExpr {
                expr: ExprKind::DecimalLiteral {
                    value,
                    spelling: spelling.clone(),
                },
                ty: Type::Decimal,
            })
        }
        Expr::Bool(value) => Ok(TypedExpr {
            expr: ExprKind::Bool(*value),
            ty: Type::Bool,
        }),
        Expr::String(value) => Ok(TypedExpr {
            expr: ExprKind::String(value.clone()),
            ty: Type::String,
        }),
        Expr::Bytes(value) => Ok(TypedExpr {
            expr: ExprKind::Bytes(value.clone()),
            ty: Type::Bytes,
        }),
        Expr::Ident(name) if context.variant_codes.borrow().contains_key(name) => {
            analyze_expr_expected(context, expr, &mut HashMap::new(), expected)
        }
        Expr::Ident(name) => {
            if let Some((target, _)) = context.validate_value_target(expr, name, &HashMap::new())?
                && !matches!(
                    target,
                    crate::resolved::ResolvedValueTarget::Const(_)
                        | crate::resolved::ResolvedValueTarget::ExternalConst
                )
            {
                return Err(SemanticError {
                    code: "E_INTERNAL_RESOLUTION",
                    message: format!("const initializer `{name}` carries a non-const target"),
                });
            }
            consts.get(name).cloned().ok_or_else(|| SemanticError {
                code: "K2002",
                message: format!(
                    "const `{name}` is undefined or declared after use; constants must be declared before use"
                ),
            })
        }
        Expr::Unary {
            op: UnaryOp::Neg,
            expr: inner,
        } => {
            // Preserve the signed literal expression until assignment so a
            // contextual quantity reports `E_NEGATIVE_QUANTITY`.
            let unary_expected =
                expected.filter(|expected| resolve_struct_type(expected) != Type::Quantity);
            let inner = analyze_const_expr(context, inner, consts, unary_expected)?;
            if !matches!(resolve_struct_type(&inner.ty), Type::Int | Type::Decimal) {
                return Err(SemanticError {
                    code: "K2003",
                    message: "const unary `-` expects int or decimal".into(),
                });
            }
            let ty = inner.ty.clone();
            fold_constant_numeric(&TypedExpr {
                expr: ExprKind::Unary {
                    op: UnaryOp::Neg,
                    expr: Box::new(inner),
                },
                ty,
            })
        }
        Expr::Call {
            name,
            args,
            argument_names,
            implicit_receiver,
        } if Builtin::from_source_name(name).is_some_and(|builtin| {
            matches!(
                builtin,
                Builtin::PointerConstructor(_)
                    | Builtin::Isqrt
                    | Builtin::Abs
                    | Builtin::Min
                    | Builtin::Max
                    | Builtin::DivCeil
                    | Builtin::Gcd
                    | Builtin::Mean
            )
        }) =>
        {
            let builtin = Builtin::from_source_name(name).expect("checked helper guard");
            let signature = builtin.signature();
            let names = signature
                .parameter_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>();
            let plan = reorder_builtin_call_arguments(
                builtin,
                name,
                args,
                argument_names.as_deref(),
                *implicit_receiver,
                &names,
                &vec![true; names.len()],
            )?;
            let mut arguments = vec![None; plan.ordered.len()];
            for index in &plan.evaluation_order {
                arguments[*index] = Some(analyze_const_expr(
                    context,
                    &plan.ordered[*index],
                    consts,
                    if matches!(builtin, Builtin::PointerConstructor(_)) {
                        Some(&Type::String)
                    } else {
                        Some(&Type::Int)
                    },
                )?);
            }
            let arguments: Vec<TypedExpr> = arguments
                .into_iter()
                .map(|argument| argument.expect("call plan covers every argument"))
                .collect();
            if builtin == Builtin::PointerConstructor(PointerConstructor::AccountId)
                && arguments.first().is_some_and(|argument| {
                    matches!(argument.kind(), ExprKind::String(value)
                        if value.contains('@')
                            && iroha_data_model::account::AccountId::parse_encoded(value).is_err())
                })
            {
                return Err(sem_err(
                    "E_CONST_INITIALIZER",
                    "const account identifiers cannot resolve live aliases; store the alias as bytes and resolve it explicitly".into(),
                ));
            }
            if matches!(builtin, Builtin::PointerConstructor(_)) {
                let argument_types = arguments
                    .iter()
                    .map(|argument| argument.ty.clone())
                    .collect::<Vec<_>>();
                canonicalize_builtin_result(
                    builtin,
                    analyze_surface_builtin_call(context, builtin, arguments, expected)
                        .inspect_err(|error| {
                            capture_builtin_argument_help(
                                context,
                                builtin,
                                error,
                                &plan.ordered,
                                &argument_types,
                            );
                        }),
                )
            } else {
                analyze_fixed_builtin_call(builtin, arguments)
            }
        }
        Expr::Binary { op, left, right }
            if matches!(
                op,
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod
            ) =>
        {
            let mut left = analyze_const_expr(context, left, consts, None)?;
            let mut right = analyze_const_expr(context, right, consts, None)?;
            if *op == BinaryOp::Mod
                && (resolve_struct_type(&left.ty) == Type::Quantity
                    || resolve_struct_type(&right.ty) == Type::Quantity
                    || expected
                        .is_some_and(|expected| resolve_struct_type(expected) == Type::Quantity))
            {
                return Err(SemanticError {
                    code: "E_QUANTITY_REMAINDER",
                    message: "quantity does not support `%`; divide with an explicit rounding mode, for example `value.div_round(divisor: d, scale: 6, mode: Rounding::floor)`"
                        .into(),
                });
            }
            coerce_contextual_numeric_literals(*op, expected, &mut left, &mut right)?;
            reject_implicit_int_decimal_mix(&left.ty, &right.ty)?;
            let result =
                arithmetic_result_type(*op, &left.ty, &right.ty).ok_or_else(|| SemanticError {
                    code: "K2003",
                    message: format!(
                        "operator {op:?} is not defined for {} and {}",
                        type_name(&left.ty),
                        type_name(&right.ty)
                    ),
                })?;
            fold_constant_numeric(&TypedExpr {
                expr: ExprKind::Binary {
                    op: *op,
                    left: Box::new(left),
                    right: Box::new(right),
                },
                ty: result,
            })
        }
        _ => Err(SemanticError {
            code: "E_CONST_INITIALIZER",
            message:
                "const initializers require constant values or canonical typed literal constructors"
                    .into(),
        }),
    }
}
fn fold_constant_numeric(expression: &TypedExpr) -> Result<TypedExpr, SemanticError> {
    match crate::checked_arithmetic::evaluate(expression) {
        Ok(Some(value)) => Ok(value.into_typed_expr()),
        Ok(None) => Err(SemanticError {
            code: "E_CONST_INITIALIZER",
            message: "numeric constant depends on a runtime value".into(),
        }),
        Err(error) => Err(SemanticError {
            code: error.code(),
            message: error.to_string(),
        }),
    }
}
fn parse_declared_param_type(
    context: &SemanticContext,
    param: &Param,
    modifiers: &FunctionModifiers,
) -> Result<TypedParam, SemanticError> {
    if modifiers.kind != FunctionKind::Private
        && !iroha_data_model::smart_contract::entrypoint::is_canonical_kotodama_identifier(
            &param.name,
        )
    {
        let type_source = param.ty.as_ref().and_then(|ty| context.type_source(ty));
        let name_source = type_source.and_then(|ty| {
            context
                .resolved_arenas
                .borrow()
                .get(&ty.source)
                .and_then(|arena| {
                    arena
                        .bindings()
                        .filter(|binding| {
                            binding.name == param.name
                                && binding.kind == crate::resolved::ResolvedBindingKind::Parameter
                        })
                        .filter_map(|binding| binding.source)
                        .filter(|name| name.range.start >= ty.range.end)
                        .min_by_key(|name| name.range.start)
                })
        });
        context.capture_help(name_source.or(type_source),
            "Use an ordinary canonical identifier for a public parameter, such as `permission_token`; keyword spellings are not valid ABI field names.".into());
        return Err(sem_err(
            "E_PUBLIC_PARAMETER_IDENTIFIER",
            format!(
                "public parameter `{}` must be a canonical Kotodama identifier",
                param.name
            ),
        ));
    }
    let ty = convert_type_expr(
        context,
        param.ty.as_ref().ok_or_else(|| SemanticError {
            code: "K2003",
            message: format!("parameter `{}` requires an explicit type", param.name),
        })?,
    )?;
    let ty = resolve_struct_type_with_context(context, &ty).inspect_err(|_| {
        context.capture_diagnostic(
            param.ty.as_ref().and_then(|ty| context.type_source(ty)),
            None,
        );
    })?;

    if modifiers.kind != FunctionKind::Private && crate::secret::type_contains_secret(&ty) {
        context.capture_diagnostic(
            param.ty.as_ref().and_then(|ty| context.type_source(ty)),
            None,
        );
        return Err(SemanticError {
            code: "E_SECRET_PUBLIC_PARAMETER",
            message: format!(
                "externally callable function cannot accept secret parameter `{}`; obtain private inputs with `crypto::private_input`",
                param.name
            ),
        });
    }
    if modifiers.kind != FunctionKind::Private && !is_supported_public_argument_type(&ty) {
        return Err(SemanticError {
            code: "K2003",
            message: format!(
                "public parameter `{}` uses unsupported V1 boundary type `{}`",
                param.name,
                type_name(&ty)
            ),
        });
    }
    if param.is_state {
        if modifiers.kind != FunctionKind::Private {
            return Err(SemanticError {
                code: "K2005",
                message: format!(
                    "state parameter `{}` is only supported on internal helper functions",
                    param.name
                ),
            });
        }
        validate_state_type(&ty)?;
    }
    Ok(TypedParam {
        name: param.name.clone(),
        ty,
        call_mode: param.call_mode,
        is_state: param.is_state,
    })
}
fn convert_capacity_expression(
    context: &SemanticContext,
    expression: &TypeExpr,
) -> Result<u8, SemanticError> {
    let node = context.validate_type_node(expression)?;
    if node.as_ref().is_some_and(|node| node.target.is_some()) {
        return Err(SemanticError {
            code: "E_INTERNAL_RESOLUTION",
            message: "capacity expression carries a resolver type-name target".into(),
        });
    }
    let value = match expression.kind() {
        TypeExpr::Const(value) => BigInt::from(*value),
        TypeExpr::ConstExpression(expression) => {
            let folded =
                static_integer_constant(context, expression).map_err(|error| SemanticError {
                    code: "E_LIST_CAPACITY_CONST",
                    message: error.message,
                })?;
            let ExprKind::IntLiteral(value) = folded.kind() else {
                unreachable!("validated static integer")
            };
            value.clone()
        }
        _ => {
            return Err(SemanticError {
                code: "E_LIST_CAPACITY_CONST",
                message: "capacity must be an integer constant expression in 1..=64".into(),
            });
        }
    };
    value
        .try_to_u64()
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| (1..=64).contains(value))
        .ok_or_else(|| SemanticError {
            code: "E_LIST_CAPACITY",
            message: format!("capacity {value} is outside 1..=64"),
        })
}
fn convert_type_expr(context: &SemanticContext, ty: &TypeExpr) -> Result<Type, SemanticError> {
    let result = convert_type_expr_inner(context, ty);
    if result.is_err() {
        context.capture_diagnostic(context.type_source(ty), None);
    }
    result
}
fn convert_type_expr_inner(
    context: &SemanticContext,
    ty: &TypeExpr,
) -> Result<Type, SemanticError> {
    let kind = ty.kind();
    let type_node = context.validate_type_node(ty)?;
    if matches!(
        kind,
        TypeExpr::Tuple(_) | TypeExpr::Const(_) | TypeExpr::ConstExpression(_)
    ) && type_node.as_ref().is_some_and(|node| node.target.is_some())
    {
        return Err(SemanticError {
            code: "E_INTERNAL_RESOLUTION",
            message: "unnamed type expression carries a resolver name target".into(),
        });
    }
    Ok(match kind {
        TypeExpr::Source { .. } | TypeExpr::Resolved { .. } => {
            unreachable!("kind() strips AST and resolved-HIR provenance wrappers")
        }
        TypeExpr::Path(s) => {
            context.validate_named_type_target(type_node.as_ref(), s)?;
            if let Some(imported) = context.external_types.borrow().get(s) {
                return Ok(imported.clone());
            }
            match s.as_str() {
                "int" => Type::Int,
                "decimal" => Type::Decimal,
                "quantity" => Type::Quantity,
                name if declared_enum_type(context, name).is_some() => {
                    declared_enum_type(context, name).expect("declared enum type")
                }
                "bool" => Type::Bool,
                "string" => Type::String,
                "bytes" => Type::Bytes,
                "DataSpaceId" => Type::DataSpaceId,
                // Recognize common Iroha types by name
                "AccountId" => Type::AccountId,
                "AssetDefinitionId" => Type::AssetDefinitionId,
                "AssetId" => Type::AssetId,
                "DomainId" => Type::DomainId,
                "Name" => Type::Name,
                "Json" => Type::Json,
                "NftId" => Type::NftId,
                "AccountView" => core_query_view_type(Builtin::QueryGetAccount)
                    .expect("account core query has a declared view"),
                "AssetView" => core_query_view_type(Builtin::QueryGetAsset)
                    .expect("asset core query has a declared view"),
                "AssetDefinitionView" => core_query_view_type(Builtin::QueryGetAssetDefinition)
                    .expect("asset definition core query has a declared view"),
                "DomainView" => core_query_view_type(Builtin::QueryGetDomain)
                    .expect("domain core query has a declared view"),
                "NftView" => core_query_view_type(Builtin::QueryGetNft)
                    .expect("NFT core query has a declared view"),
                other => {
                    let is_declared_struct = context.structs.borrow().contains_key(other);
                    if !is_declared_struct {
                        return Err(SemanticError {
                            code: "K2002",
                            message: format!("unknown type `{other}`"),
                        });
                    }
                    Type::NamedStruct(other.to_string())
                }
            }
        }
        TypeExpr::Generic { base, args } => {
            context.validate_named_type_target(type_node.as_ref(), base)?;
            if base == "StateMap" {
                if args.len() != 2 {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "StateMap expects two type parameters".into(),
                    });
                }
                let k = convert_type_expr(context, &args[0])?;
                let v = convert_type_expr(context, &args[1])?;
                Type::StateMap(Box::new(k), Box::new(v))
            } else if base == "StateCursor" {
                if args.len() != 1 {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "StateCursor expects one canonical map-key type".into(),
                    });
                }
                let key = convert_type_expr(context, &args[0])?;
                if !is_supported_durable_key_type(&key) {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "StateCursor requires a canonical durable StateMap key type"
                            .into(),
                    });
                }
                Type::StateCursor(Box::new(key))
            } else if base == "StatePage" {
                if args.len() != 3 {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "StatePage expects key, value, and capacity parameters".into(),
                    });
                }
                let key = convert_type_expr(context, &args[0])?;
                let value = convert_type_expr(context, &args[1])?;
                let capacity = convert_capacity_expression(context, &args[2])?;
                state_page_type(key, value, capacity)?
            } else if base == "Secret" {
                if !context.zk_enabled {
                    return Err(SemanticError {
                        code: "E_SECRET_REQUIRES_ZK",
                        message:
                            "Secret<T> is available only when compiler build configuration enables ZK mode"
                                .into(),
                    });
                }
                if args.len() != 1 {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "Secret expects one type parameter".into(),
                    });
                }
                let inner = convert_type_expr(context, &args[0])?;
                if !matches!(inner, Type::Int | Type::Decimal | Type::Quantity) {
                    return Err(SemanticError {
                        code: "E_SECRET_PAYLOAD_TYPE",
                        message: format!(
                            "Secret<{}> is unsupported; the V1 private-input ABI supplies Secret<int>, Secret<decimal>, and Secret<quantity>",
                            type_name(&inner)
                        ),
                    });
                }
                Type::Secret(Box::new(inner))
            } else if base == "Option" {
                if args.len() != 1 {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "Option expects one type parameter".into(),
                    });
                }
                Type::Option(Box::new(convert_type_expr(context, &args[0])?))
            } else if base == "Result" {
                if args.len() != 2 {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "Result expects two type parameters".into(),
                    });
                }
                Type::Result(
                    Box::new(convert_type_expr(context, &args[0])?),
                    Box::new(convert_type_expr(context, &args[1])?),
                )
            } else if base == "List" {
                if args.len() != 2 {
                    return Err(SemanticError {
                        code: "E_LIST_TYPE_ARITY",
                        message: "List expects an element type and capacity".into(),
                    });
                }
                let element = convert_type_expr(context, &args[0])?;
                let capacity = convert_capacity_expression(context, &args[1])?;
                if list_element_contains_resource_handle(&element) {
                    return Err(SemanticError {
                        code: "E_LIST_RESOURCE_ELEMENT",
                        message: format!(
                            "List elements cannot contain resource handle type `{}`",
                            type_name(&element)
                        ),
                    });
                }
                Type::List(Box::new(element), capacity)
            } else if base == "QueryPage" {
                if args.len() != 1 {
                    return Err(SemanticError {
                        code: "K2003",
                        message: "QueryPage expects one core query view type parameter".into(),
                    });
                }
                query_page_type(convert_type_expr(context, &args[0])?)?
            } else {
                return Err(SemanticError {
                    code: "K2002",
                    message: format!("unknown generic type `{base}`"),
                });
            }
        }
        TypeExpr::Tuple(elems) => {
            if elems.is_empty() {
                Type::Unit
            } else {
                let mut out = Vec::new();
                for e in elems {
                    out.push(convert_type_expr(context, e)?);
                }
                Type::Tuple(out)
            }
        }
        TypeExpr::Const(value) => {
            return Err(SemanticError {
                code: "E_CONST_CAPACITY_CONTEXT",
                message: format!(
                    "compile-time integer `{value}` is only valid as the capacity in List<T, N>"
                ),
            });
        }
        TypeExpr::ConstExpression(_) => {
            return Err(SemanticError { code: "E_CONST_CAPACITY_CONTEXT", message: "integer constant expressions are only valid in List and StatePage capacity positions".into() });
        }
    })
}
fn ensure_assignable(expected: &Type, actual: &Type) -> Result<(), SemanticError> {
    let expected = resolve_struct_type(expected);
    let actual = resolve_struct_type(actual);
    if expected == actual {
        return Ok(());
    }
    match (&expected, &actual) {
        (Type::StateMap(ek, ev), Type::StateMap(ak, av)) => {
            ensure_assignable(ek, ak)?;
            ensure_assignable(ev, av)
        }
        (Type::Option(expected), Type::Option(actual)) => ensure_assignable(expected, actual),
        (Type::Result(expected_ok, expected_err), Type::Result(actual_ok, actual_err)) => {
            ensure_assignable(expected_ok, actual_ok)?;
            ensure_assignable(expected_err, actual_err)
        }
        (
            Type::List(expected_element, expected_capacity),
            Type::List(actual_element, actual_capacity),
        ) if expected_capacity == actual_capacity => {
            ensure_assignable(expected_element, actual_element)
        }
        (Type::Tuple(exp_elems), Type::Tuple(act_elems)) => {
            if exp_elems.len() != act_elems.len() {
                return Err(SemanticError {
                    code: "E_TYPE_ANNOTATION_MISMATCH",
                    message: format!(
                        "expected a tuple of length {}, found one of length {}",
                        exp_elems.len(),
                        act_elems.len()
                    ),
                });
            }
            for (e, a) in exp_elems.iter().zip(act_elems.iter()) {
                ensure_assignable(e, a)?;
            }
            Ok(())
        }
        // Forward struct references are nominal until their declarations are
        // expanded; unrelated names must never become assignable.
        (Type::NamedStruct(expected_name), Type::NamedStruct(actual_name))
            if expected_name == actual_name =>
        {
            Ok(())
        }
        _ => Err(SemanticError {
            code: "E_TYPE_ANNOTATION_MISMATCH",
            message: format!(
                "expected {}, found {}",
                type_help::quoted(&expected),
                type_help::quoted(&actual)
            ),
        }),
    }
}
/// A private helper's first parameter selects receiver syntax before native methods.
/// Only exact types and the ordinary outer-list boundary widening participate.
pub(crate) fn user_receiver_accepts(expected: &Type, actual: &Type) -> bool {
    let expected = resolve_struct_type(expected);
    let actual = resolve_struct_type(actual);
    expected == actual
        || matches!((&expected, &actual),
        (Type::List(expected_element, expected_capacity), Type::List(actual_element, actual_capacity))
        if expected_element == actual_element && actual_capacity < expected_capacity)
}
/// Call and return boundaries may copy an exactly typed List into larger outer storage.
fn ensure_boundary_assignable_and_coerce(
    expected: &Type,
    expr: &mut TypedExpr,
) -> Result<(), SemanticError> {
    if let (
        Type::List(expected_element, expected_capacity),
        Type::List(actual_element, actual_capacity),
    ) = (resolve_struct_type(expected), resolve_struct_type(&expr.ty))
        && expected_element == actual_element
        && actual_capacity < expected_capacity
    {
        let source = expr.clone();
        *expr = TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Intrinsic(CompilerIntrinsic::ListWiden),
                args: vec![source],
            },
            ty: resolve_struct_type(expected),
        };
        return Ok(());
    }
    ensure_assignable_and_coerce(expected, expr)
}
fn ensure_assignable_and_coerce(
    expected: &Type,
    expr: &mut TypedExpr,
) -> Result<(), SemanticError> {
    if let Err(error) = ensure_assignable(expected, &expr.ty) {
        if resolve_struct_type(expected) == Type::Decimal
            && resolve_struct_type(&expr.ty) == Type::Int
            && int_literal_expression(expr)
        {
            let inner = expr.clone();
            let converted = TypedExpr {
                expr: ExprKind::NumericCast {
                    expr: Box::new(inner),
                },
                ty: Type::Decimal,
            };
            *expr = fold_numeric_literal_cast(converted)?;
            return Ok(());
        }
        if resolve_struct_type(expected) == Type::Quantity
            && matches!(resolve_struct_type(&expr.ty), Type::Int | Type::Decimal)
            && exact_numeric_literal_expression(expr)
        {
            if numeric_literal_is_negative(expr) {
                return Err(SemanticError {
                    code: "E_NEGATIVE_QUANTITY",
                    message: "a contextual quantity literal cannot be negative".into(),
                });
            }
            let inner = expr.clone();
            let converted = TypedExpr {
                expr: ExprKind::NumericCast {
                    expr: Box::new(inner),
                },
                ty: Type::Quantity,
            };
            *expr = fold_numeric_literal_cast(converted)?;
            return Ok(());
        }
        if let ExprKind::Call { target: name, .. } | ExprKind::NamedCall { target: name, .. } =
            expr.kind()
            && let Some(builtin) = name.builtin()
            && core_query_view_type(builtin).is_some()
        {
            let query_result = match &expr.ty {
                Type::Option(inner) => match inner.as_ref() {
                    Type::Struct { name, .. } | Type::NamedStruct(name) => {
                        format!("Option<{name}>")
                    }
                    other => format!("Option<{}>", type_name(other)),
                },
                Type::Struct { name, .. } | Type::NamedStruct(name) => name.clone(),
                other => type_name(other),
            };
            return Err(SemanticError {
                code: "E_QUERY_RESULT_TYPE",
                message: format!(
                    "typed core query `{}` returns `{}`, not `{}`; byte-returning compatibility is not part of Kotodama V1",
                    builtin.source_name(),
                    query_result,
                    type_name(expected)
                ),
            });
        }
        return Err(error);
    }
    Ok(())
}
fn fold_numeric_literal_cast(converted: TypedExpr) -> Result<TypedExpr, SemanticError> {
    match crate::checked_arithmetic::evaluate(&converted) {
        Ok(Some(value)) => Ok(value.into_typed_expr()),
        Ok(None) => Err(SemanticError {
            code: "E_INTERNAL_NUMERIC_MATRIX",
            message: "contextual numeric literal unexpectedly depends on a runtime value".into(),
        }),
        Err(error) => Err(SemanticError {
            code: error.code(),
            message: error.to_string(),
        }),
    }
}
fn int_literal_expression(expr: &TypedExpr) -> bool {
    match expr.kind() {
        ExprKind::IntLiteral(_) => true,
        ExprKind::Unary {
            op: UnaryOp::Neg,
            expr,
        } => int_literal_expression(expr),
        _ => false,
    }
}
fn exact_numeric_literal_expression(expr: &TypedExpr) -> bool {
    match expr.kind() {
        ExprKind::IntLiteral(_) | ExprKind::DecimalLiteral { .. } => true,
        ExprKind::Unary {
            op: UnaryOp::Neg,
            expr,
        } => exact_numeric_literal_expression(expr),
        _ => false,
    }
}
/// Check an assignment to a local, explaining inferred types when they do not fit.
fn inferred_assignment(
    context: &SemanticContext,
    statement: &Statement,
    name: &str,
    expected: &Type,
    value: &mut TypedExpr,
) -> Result<(), SemanticError> {
    let Err(mut error) = ensure_assignable_and_coerce(expected, value) else {
        return Ok(());
    };
    if error.code == "E_TYPE_ANNOTATION_MISMATCH"
        && let Some(label) = context.inferred_local_label(name, expected)
    {
        error.code = "K2003";
        error.message = format!(
            "`{name}` has inferred type {}, so it cannot be assigned {}",
            type_help::quoted(expected),
            type_help::quoted(&value.ty)
        );
        if let Some(primary) = context.statement_source(statement) {
            let mut diagnostic = crate::semantic_diagnostics::SemanticDiagnostic::at(primary, None)
                .with_help(format!(
                    "Declare the type you need at the binding, for example `var {} {name} = ...;`.",
                    render_type_name(&value.ty)
                ));
            diagnostic.labels.push(label);
            context.capture_structured(diagnostic);
        }
    }
    Err(error)
}
fn assign_op_to_binary(op: AssignOp) -> Option<BinaryOp> {
    match op {
        AssignOp::Set => None,
        AssignOp::Add => Some(BinaryOp::Add),
        AssignOp::Sub => Some(BinaryOp::Sub),
        AssignOp::Mul => Some(BinaryOp::Mul),
        AssignOp::Div => Some(BinaryOp::Div),
        AssignOp::Mod => Some(BinaryOp::Mod),
    }
}
pub(crate) fn resolve_struct_type(ty: &Type) -> Type {
    match ty {
        Type::NamedStruct(_) => ty.clone(),
        Type::StateMap(key, value) => Type::StateMap(
            Box::new(resolve_struct_type(key)),
            Box::new(resolve_struct_type(value)),
        ),
        Type::Option(inner) => Type::Option(Box::new(resolve_struct_type(inner))),
        Type::Result(ok, err) => Type::Result(
            Box::new(resolve_struct_type(ok)),
            Box::new(resolve_struct_type(err)),
        ),
        Type::List(element, capacity) => {
            Type::List(Box::new(resolve_struct_type(element)), *capacity)
        }
        Type::Secret(inner) => Type::Secret(Box::new(resolve_struct_type(inner))),
        Type::Tuple(items) => Type::Tuple(items.iter().map(resolve_struct_type).collect()),
        Type::Struct { .. } => ty.clone(),
        _ => ty.clone(),
    }
}
fn resolve_struct_type_with_context(
    context: &SemanticContext,
    ty: &Type,
) -> Result<Type, SemanticError> {
    if let Type::NamedStruct(name) = ty
        && !context.resolved_named_types.borrow().contains_key(name)
    {
        return Err(SemanticError {
            code: "K2002",
            message: format!("unknown canonical struct type `{name}`"),
        });
    }
    validate_use_site_type_resolution_budget(context, ty)?;
    let resolved = materialize_struct_type_with_context(context, ty);
    if !context.contracts.borrow().is_empty() {
        contract_imports::validate_reference_containers(&resolved)?;
    }
    Ok(resolved)
}
fn validate_use_site_type_resolution_budget(
    context: &SemanticContext,
    ty: &Type,
) -> Result<(), SemanticError> {
    let resources = measure_expanded_type(ty, &context.resolved_named_type_resources.borrow());
    if resources.depth > MAX_NESTING_DEPTH {
        return Err(SemanticError {
            code: "K2008",
            message: format!(
                "expanded use-site value type exceeds the V1 nesting limit of {MAX_NESTING_DEPTH} levels"
            ),
        });
    }
    if resources.nodes > MAX_EXPANDED_TYPE_NODES {
        return Err(SemanticError {
            code: "K2008",
            message: format!(
                "expanded use-site value type exceeds the V1 resource limit of {MAX_EXPANDED_TYPE_NODES} type nodes"
            ),
        });
    }
    Ok(())
}
fn materialize_struct_type_with_context(context: &SemanticContext, ty: &Type) -> Type {
    match ty {
        Type::NamedStruct(name) => context
            .resolved_named_types
            .borrow()
            .get(name)
            .cloned()
            .unwrap_or_else(|| ty.clone()),
        Type::StateMap(key, value) => Type::StateMap(
            Box::new(materialize_struct_type_with_context(context, key)),
            Box::new(materialize_struct_type_with_context(context, value)),
        ),
        Type::Option(inner) => Type::Option(Box::new(materialize_struct_type_with_context(
            context, inner,
        ))),
        Type::Result(ok, err) => Type::Result(
            Box::new(materialize_struct_type_with_context(context, ok)),
            Box::new(materialize_struct_type_with_context(context, err)),
        ),
        Type::List(element, capacity) => Type::List(
            Box::new(materialize_struct_type_with_context(context, element)),
            *capacity,
        ),
        Type::Secret(inner) => Type::Secret(Box::new(materialize_struct_type_with_context(
            context, inner,
        ))),
        Type::Tuple(items) => Type::Tuple(
            items
                .iter()
                .map(|item| materialize_struct_type_with_context(context, item))
                .collect(),
        ),
        Type::Struct { .. } => ty.clone(),
        _ => ty.clone(),
    }
}
fn normalize_namespaced(name: &str) -> String {
    if let Some(builtin) = Builtin::from_source_name(name) {
        return builtin.name().to_owned();
    }
    String::from(name)
}
fn block_has_return_value(block: &super::ast::Block) -> bool {
    block.statements.iter().any(stmt_has_return_value)
}
fn stmt_has_return_value(stmt: &super::ast::Statement) -> bool {
    use super::ast::Statement as S;
    match stmt.kind() {
        S::Return(Some(_)) => true,
        S::If {
            then_branch,
            else_branch,
            ..
        } => {
            block_has_return_value(then_branch)
                || else_branch
                    .as_ref()
                    .map(block_has_return_value)
                    .unwrap_or(false)
        }
        S::While { body, .. } => block_has_return_value(body),
        S::For { body, .. } => block_has_return_value(body),
        S::ForEachMap { body, .. } => block_has_return_value(body),
        _ => false,
    }
}
// NOTE: `TypedProgram` is defined earlier in this file with seiyaku metadata.
#[derive(Clone, Debug, PartialEq)]
pub enum TypedItem {
    Function(TypedFunction),
}
#[derive(Debug, PartialEq, Clone)]
pub struct TypedTrigger {
    pub id: TriggerId,
    pub call: TriggerCall,
    pub filter: EventFilterBox,
    pub repeats: Repeats,
    pub authority: Option<AccountId>,
    pub metadata: Metadata,
}
#[derive(Debug, Clone, PartialEq)]
pub struct TypedFunction {
    pub name: String,
    pub params: Vec<String>,
    pub param_types: Vec<TypedParam>,
    pub body: TypedBlock,
    pub ret_ty: Option<Type>,
    pub modifiers: FunctionModifiers,
    pub location: super::ast::SourceLocation,
    /// Exact complete function declaration range, when source-backed.
    pub source: Option<crate::source::SourceRange>,
    /// Exact declared function/lifecycle name range, when source-backed.
    pub name_source: Option<crate::source::SourceRange>,
}

#[derive(Debug, Clone)]
pub struct TypedBlock {
    pub statements: Vec<TypedStatement>,
    /// Final expression without a semicolon.
    pub tail: Option<Box<TypedExpr>>,
    /// Source ranges of the statements and tail, used for diagnostics and debug sidecars.
    ///
    /// Provenance never participates in typed-HIR equality or artifact identity.
    /// Lowering transports it separately from executable operations.
    pub(crate) provenance: TypedBlockProvenance,
}
impl TypedBlock {
    /// Construct a block without source provenance.
    #[must_use]
    pub fn new(statements: Vec<TypedStatement>, tail: Option<Box<TypedExpr>>) -> Self {
        Self {
            statements,
            tail,
            provenance: TypedBlockProvenance::default(),
        }
    }
    /// Source range of the AST statement that produced `statements[index]`.
    pub(crate) fn statement_source(&self, index: usize) -> Option<crate::source::SourceRange> {
        self.provenance.statements.get(index).copied().flatten()
    }
    /// Source range of the tail expression.
    pub(crate) fn tail_source(&self) -> Option<crate::source::SourceRange> {
        self.provenance.tail
    }
    /// Insert compiler-created statements before the block's own statements.
    ///
    /// The inserted statements have no source of their own, so provenance stays
    /// aligned: `statement_source(i)` still names the AST statement that
    /// produced `statements[i]`.
    pub(crate) fn prepend_unsourced(&mut self, mut statements: Vec<TypedStatement>) {
        let count = statements.len();
        statements.append(&mut self.statements);
        self.statements = statements;
        if !self.provenance.statements.is_empty() {
            self.provenance
                .statements
                .splice(0..0, std::iter::repeat_n(None, count));
        }
    }
}
impl PartialEq for TypedBlock {
    fn eq(&self, other: &Self) -> bool {
        self.statements == other.statements && self.tail == other.tail
    }
}
/// Non-executable source provenance retained beside one typed block.
#[derive(Debug, Clone, Default)]
pub(crate) struct TypedBlockProvenance {
    /// One entry per typed statement; desugared statements share their AST source.
    pub(crate) statements: Vec<Option<crate::source::SourceRange>>,
    /// Source of the block tail expression.
    pub(crate) tail: Option<crate::source::SourceRange>,
}

pub enum TypedStatement {
    Let {
        name: String,
        value: TypedExpr,
    },
    Expr(TypedExpr),
    Return(Option<TypedExpr>),
    Break,
    Continue,
    If {
        cond: TypedExpr,
        then_branch: TypedBlock,
        else_branch: Option<TypedBlock>,
    },
    /// Statement `if let`; unlike the expression form, `else` may be absent.
    IfLet {
        pattern: TypedSumPattern,
        value: TypedExpr,
        then_branch: TypedBlock,
        else_branch: Option<TypedBlock>,
    },
    While {
        cond: TypedExpr,
        body: TypedBlock,
    },
    For {
        line: usize,
        init: Option<Box<TypedStatement>>,
        cond: Option<TypedExpr>,
        step: Option<Box<TypedStatement>>,
        body: TypedBlock,
    },
    /// Iterate a materialized bounded List, binding its element before the body.
    ForEachMap {
        key: String,
        value: Option<String>,
        map: TypedExpr,
        body: TypedBlock,
    },
    /// Map set operation: `map[key] = value`.
    MapSet {
        map: TypedExpr,
        key: TypedExpr,
        value: Box<TypedExpr>,
    },
}
impl TypedExpr {
    /// View the typed expression kind.
    #[must_use]
    pub const fn kind(&self) -> &ExprKind {
        &self.expr
    }
    /// Mutably view the typed expression kind.
    #[must_use]
    pub const fn kind_mut(&mut self) -> &mut ExprKind {
        &mut self.expr
    }
}
impl TypedStatement {
    /// View the typed statement.
    #[must_use]
    pub const fn kind(&self) -> &Self {
        self
    }
    /// Mutably view the typed statement.
    #[must_use]
    pub const fn kind_mut(&mut self) -> &mut Self {
        self
    }
}
/// Return call operands with runtime evaluation semantics.
///
/// Active-only sums use dedicated expression nodes, so ordinary calls always
/// evaluate every argument in source order.
fn evaluated_call_args<'a>(_target: &CallTarget, args: &'a [TypedExpr]) -> &'a [TypedExpr] {
    args
}
fn block_effects(context: &SemanticContext, block: &TypedBlock) -> FunctionEffects {
    let mut effects = FunctionEffects::default();
    for statement in &block.statements {
        effects.merge_from(statement_effects(context, statement));
    }
    if let Some(tail) = &block.tail {
        effects.merge_from(expr_effects(context, tail));
    }
    effects
}

fn statement_effects(context: &SemanticContext, statement: &TypedStatement) -> FunctionEffects {
    match statement.kind() {
        TypedStatement::Let { name, value } => {
            let mut effects = expr_effects(context, value);
            effects.mutates_durable_state |= is_state_binding(context, name);
            effects
        }
        TypedStatement::Expr(expr) | TypedStatement::Return(Some(expr)) => {
            expr_effects(context, expr)
        }
        TypedStatement::MapSet { map, key, value } => {
            let mut effects = expr_effects(context, map);
            effects.merge_from(expr_effects(context, key));
            effects.merge_from(expr_effects(context, value));
            effects.mutates_durable_state |= typed_map_expr_is_state(context, map);
            effects
        }
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            let mut effects = expr_effects(context, cond);
            effects.merge_from(block_effects(context, then_branch));
            if let Some(branch) = else_branch {
                effects.merge_from(block_effects(context, branch));
            }
            effects
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            let mut effects = expr_effects(context, value);
            effects.merge_from(block_effects(context, then_branch));
            if let Some(branch) = else_branch {
                effects.merge_from(block_effects(context, branch));
            }
            effects
        }
        TypedStatement::While { cond, body } => {
            let mut effects = expr_effects(context, cond);
            effects.merge_from(block_effects(context, body));
            effects
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            let mut effects = FunctionEffects::default();
            if let Some(init) = init.as_deref() {
                effects.merge_from(statement_effects(context, init));
            }
            if let Some(cond) = cond {
                effects.merge_from(expr_effects(context, cond));
            }
            if let Some(step) = step.as_deref() {
                effects.merge_from(statement_effects(context, step));
            }
            effects.merge_from(block_effects(context, body));
            effects
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            let mut effects = expr_effects(context, map);
            effects.merge_from(block_effects(context, body));
            effects
        }
        TypedStatement::Return(None) | TypedStatement::Break | TypedStatement::Continue => {
            FunctionEffects::default()
        }
    }
}

fn expr_effects(context: &SemanticContext, expression: &TypedExpr) -> FunctionEffects {
    match expression.kind() {
        ExprKind::Call { target: name, args }
        | ExprKind::NamedCall {
            target: name, args, ..
        } => {
            let mut effects = FunctionEffects {
                host_side_effects: name.intrinsic() == Some(CompilerIntrinsic::EmitEvent)
                    || matches!(name, CallTarget::Contract(method) if method.descriptor().kind == iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage),
                ..FunctionEffects::default()
            };
            if let Some(builtin) = name.builtin() {
                let builtin_effects = builtin.spec().effects;
                effects.host_side_effects = builtin_effects.host_side_effects;
                effects.emits_instructions = builtin_effects.emits_instructions;
                effects.mutates_durable_state = builtin_effects.mutates_durable_state;
                if builtin == Builtin::GetOrInsert {
                    effects.mutates_durable_state |= args
                        .first()
                        .is_some_and(|arg| typed_map_expr_is_state(context, arg));
                }
            }
            for argument in evaluated_call_args(name, args) {
                effects.merge_from(expr_effects(context, argument));
            }
            effects
        }
        ExprKind::Binary { left, right, .. } => {
            let mut effects = expr_effects(context, left);
            effects.merge_from(expr_effects(context, right));
            effects
        }
        ExprKind::Unary { expr, .. }
        | ExprKind::NumericCast { expr }
        | ExprKind::NumericTryCast { expr }
        | ExprKind::OptionSome { value: expr }
        | ExprKind::ResultOk { value: expr }
        | ExprKind::ResultErr { error: expr }
        | ExprKind::Propagate { value: expr }
        | ExprKind::Member { object: expr, .. } => expr_effects(context, expr),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            let mut effects = expr_effects(context, cond);
            effects.merge_from(expr_effects(context, then_expr));
            effects.merge_from(expr_effects(context, else_expr));
            effects
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let mut effects = expr_effects(context, condition);
            effects.merge_from(block_effects(context, then_branch));
            effects.merge_from(block_effects(context, else_branch));
            effects
        }
        ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            let mut effects = expr_effects(context, value);
            effects.merge_from(block_effects(context, then_branch));
            effects.merge_from(block_effects(context, else_branch));
            effects
        }
        ExprKind::Match { value, arms } => {
            let mut effects = expr_effects(context, value);
            for arm in arms {
                effects.merge_from(block_effects(context, &arm.body));
            }
            effects
        }
        ExprKind::Tuple(items) | ExprKind::List(items) | ExprKind::JsonArray(items) => {
            let mut effects = FunctionEffects::default();
            for item in items {
                effects.merge_from(expr_effects(context, item));
            }
            effects
        }
        ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            let mut effects = expr_effects(context, source);
            effects.merge_from(expr_effects(context, expression));
            if let Some(condition) = condition {
                effects.merge_from(expr_effects(context, condition));
            }
            effects
        }
        ExprKind::StructLiteral { fields, .. } | ExprKind::JsonObject(fields) => {
            let mut effects = FunctionEffects::default();
            for (_, value) in fields {
                effects.merge_from(expr_effects(context, value));
            }
            effects
        }
        ExprKind::Index { target, index } => {
            let mut effects = expr_effects(context, target);
            effects.merge_from(expr_effects(context, index));
            effects
        }
        ExprKind::VariantCode(_)
        | ExprKind::IntLiteral(_)
        | ExprKind::DecimalLiteral { .. }
        | ExprKind::OptionNone
        | ExprKind::Bool(_)
        | ExprKind::String(_)
        | ExprKind::Bytes(_)
        | ExprKind::Ident(_) => FunctionEffects::default(),
    }
}

fn is_state_identifier(context: &SemanticContext, name: &str) -> bool {
    context.states.borrow().contains_key(name)
}
fn is_state_param_name(context: &SemanticContext, name: &str) -> bool {
    context.current_state_param_names.borrow().contains(name)
}
fn is_state_binding(context: &SemanticContext, name: &str) -> bool {
    is_state_identifier(context, name) || is_state_param_name(context, name)
}
fn canonical_state_hint(name: &str) -> String {
    let base = name.split('#').next().unwrap_or(name);
    format!("state:{base}")
}
fn mark_state_read(state_names: &HashSet<String>, name: &str, reads: &mut IndexSet<String>) {
    if state_names.contains(name.split('#').next().unwrap_or(name)) {
        reads.insert(canonical_state_hint(name));
    }
}
fn mark_state_write(state_names: &HashSet<String>, name: &str, writes: &mut IndexSet<String>) {
    if state_names.contains(name.split('#').next().unwrap_or(name)) {
        writes.insert(canonical_state_hint(name));
    }
}
fn collect_state_accesses_block(
    state_names: &HashSet<String>,
    block: &TypedBlock,
    reads: &mut IndexSet<String>,
    writes: &mut IndexSet<String>,
) {
    for stmt in &block.statements {
        collect_state_accesses_statement(state_names, stmt, reads, writes);
    }
    if let Some(tail) = &block.tail {
        collect_state_accesses_expr(state_names, tail, reads, writes);
    }
}
fn collect_state_accesses_statement(
    state_names: &HashSet<String>,
    stmt: &TypedStatement,
    reads: &mut IndexSet<String>,
    writes: &mut IndexSet<String>,
) {
    match stmt.kind() {
        TypedStatement::Let { name, value } => {
            collect_state_accesses_expr(state_names, value, reads, writes);
            mark_state_write(state_names, name, writes);
        }
        TypedStatement::Expr(expr) => collect_state_accesses_expr(state_names, expr, reads, writes),
        TypedStatement::Return(Some(expr)) => {
            collect_state_accesses_expr(state_names, expr, reads, writes);
        }
        TypedStatement::Return(None) | TypedStatement::Break | TypedStatement::Continue => {}
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_state_accesses_expr(state_names, cond, reads, writes);
            collect_state_accesses_block(state_names, then_branch, reads, writes);
            if let Some(b) = else_branch {
                collect_state_accesses_block(state_names, b, reads, writes);
            }
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_state_accesses_expr(state_names, value, reads, writes);
            collect_state_accesses_block(state_names, then_branch, reads, writes);
            if let Some(block) = else_branch {
                collect_state_accesses_block(state_names, block, reads, writes);
            }
        }
        TypedStatement::While { cond, body } => {
            collect_state_accesses_expr(state_names, cond, reads, writes);
            collect_state_accesses_block(state_names, body, reads, writes);
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init_stmt) = init.as_deref() {
                collect_state_accesses_statement(state_names, init_stmt, reads, writes);
            }
            if let Some(cond_expr) = cond {
                collect_state_accesses_expr(state_names, cond_expr, reads, writes);
            }
            if let Some(step_stmt) = step.as_deref() {
                collect_state_accesses_statement(state_names, step_stmt, reads, writes);
            }
            collect_state_accesses_block(state_names, body, reads, writes);
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            collect_state_accesses_expr(state_names, map, reads, writes);
            collect_state_accesses_block(state_names, body, reads, writes);
        }
        TypedStatement::MapSet { map, key, value } => {
            collect_state_accesses_expr(state_names, map, reads, writes);
            collect_state_accesses_expr(state_names, key, reads, writes);
            collect_state_accesses_expr(state_names, value, reads, writes);
            if let ExprKind::Ident(name) = map.kind() {
                mark_state_write(state_names, name, writes);
            }
        }
    }
}
fn collect_state_accesses_expr(
    state_names: &HashSet<String>,
    expr: &TypedExpr,
    reads: &mut IndexSet<String>,
    writes: &mut IndexSet<String>,
) {
    match expr.kind() {
        ExprKind::Ident(name) => mark_state_read(state_names, name, reads),
        ExprKind::Binary { left, right, .. } => {
            collect_state_accesses_expr(state_names, left, reads, writes);
            collect_state_accesses_expr(state_names, right, reads, writes);
        }
        ExprKind::Unary { expr: inner, .. }
        | ExprKind::NumericCast { expr: inner }
        | ExprKind::NumericTryCast { expr: inner }
        | ExprKind::OptionSome { value: inner }
        | ExprKind::ResultOk { value: inner }
        | ExprKind::ResultErr { error: inner }
        | ExprKind::Propagate { value: inner } => {
            collect_state_accesses_expr(state_names, inner, reads, writes)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_state_accesses_expr(state_names, cond, reads, writes);
            collect_state_accesses_expr(state_names, then_expr, reads, writes);
            collect_state_accesses_expr(state_names, else_expr, reads, writes);
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_state_accesses_expr(state_names, condition, reads, writes);
            collect_state_accesses_block(state_names, then_branch, reads, writes);
            collect_state_accesses_block(state_names, else_branch, reads, writes);
        }
        ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_state_accesses_expr(state_names, value, reads, writes);
            collect_state_accesses_block(state_names, then_branch, reads, writes);
            collect_state_accesses_block(state_names, else_branch, reads, writes);
        }
        ExprKind::Match { value, arms } => {
            collect_state_accesses_expr(state_names, value, reads, writes);
            for arm in arms {
                collect_state_accesses_block(state_names, &arm.body, reads, writes);
            }
        }
        ExprKind::Tuple(items) | ExprKind::List(items) => {
            for item in items {
                collect_state_accesses_expr(state_names, item, reads, writes);
            }
        }
        ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            collect_state_accesses_expr(state_names, source, reads, writes);
            collect_state_accesses_expr(state_names, expression, reads, writes);
            if let Some(condition) = condition {
                collect_state_accesses_expr(state_names, condition, reads, writes);
            }
        }
        ExprKind::StructLiteral { fields, .. } => {
            for (_, value) in fields {
                collect_state_accesses_expr(state_names, value, reads, writes);
            }
        }
        ExprKind::JsonObject(entries) => {
            for (_, value) in entries {
                collect_state_accesses_expr(state_names, value, reads, writes);
            }
        }
        ExprKind::JsonArray(items) => {
            for item in items {
                collect_state_accesses_expr(state_names, item, reads, writes);
            }
        }
        ExprKind::Member { object, .. } => {
            collect_state_accesses_expr(state_names, object, reads, writes)
        }
        ExprKind::Index { target, index } => {
            collect_state_accesses_expr(state_names, target, reads, writes);
            collect_state_accesses_expr(state_names, index, reads, writes);
        }
        ExprKind::Call { target: name, args }
        | ExprKind::NamedCall {
            target: name, args, ..
        } => {
            if matches!(
                name.builtin(),
                Some(Builtin::GetOrInsert | Builtin::StateMapRemove)
            ) && let Some(map_name) = args.first().and_then(|argument| match argument.kind() {
                ExprKind::Ident(map_name) => Some(map_name),
                _ => None,
            }) {
                mark_state_write(state_names, map_name, writes);
            }
            for arg in evaluated_call_args(name, args) {
                collect_state_accesses_expr(state_names, arg, reads, writes);
            }
        }
        ExprKind::Bool(_)
        | ExprKind::VariantCode(_)
        | ExprKind::IntLiteral(_)
        | ExprKind::DecimalLiteral { .. }
        | ExprKind::OptionNone
        | ExprKind::String(_)
        | ExprKind::Bytes(_) => {}
    }
}
pub fn function_state_accesses(
    func: &TypedFunction,
    states: &[TypedStateDecl],
) -> (IndexSet<String>, IndexSet<String>) {
    crate::session::run_with_compiler_stack(move || function_state_accesses_inline(func, states))
        .expect("compiler must allocate the bounded stack required to inspect typed state access")
}
fn function_state_accesses_inline(
    func: &TypedFunction,
    states: &[TypedStateDecl],
) -> (IndexSet<String>, IndexSet<String>) {
    let state_names = states
        .iter()
        .map(|state| state.name.clone())
        .collect::<HashSet<_>>();
    let mut reads = IndexSet::new();
    let mut writes = IndexSet::new();
    collect_state_accesses_block(&state_names, &func.body, &mut reads, &mut writes);
    (reads, writes)
}
fn collect_called_functions(context: &SemanticContext, block: &TypedBlock) -> IndexSet<String> {
    let mut calls = IndexSet::new();
    collect_called_functions_into(context, block, &mut calls);
    calls
}
fn collect_called_functions_into(
    context: &SemanticContext,
    block: &TypedBlock,
    calls: &mut IndexSet<String>,
) {
    for stmt in &block.statements {
        collect_calls_in_statement(context, stmt, calls);
    }
    if let Some(tail) = &block.tail {
        collect_calls_in_expr(context, tail, calls);
    }
}
fn collect_calls_in_statement(
    context: &SemanticContext,
    stmt: &TypedStatement,
    calls: &mut IndexSet<String>,
) {
    match stmt.kind() {
        TypedStatement::Let { value, .. } => collect_calls_in_expr(context, value, calls),
        TypedStatement::Expr(expr) => collect_calls_in_expr(context, expr, calls),
        TypedStatement::Return(Some(expr)) => collect_calls_in_expr(context, expr, calls),
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_calls_in_expr(context, cond, calls);
            collect_called_functions_into(context, then_branch, calls);
            if let Some(b) = else_branch {
                collect_called_functions_into(context, b, calls);
            }
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_calls_in_expr(context, value, calls);
            collect_called_functions_into(context, then_branch, calls);
            if let Some(block) = else_branch {
                collect_called_functions_into(context, block, calls);
            }
        }
        TypedStatement::While { cond, body } => {
            collect_calls_in_expr(context, cond, calls);
            collect_called_functions_into(context, body, calls);
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            if let Some(init_stmt) = init.as_deref() {
                collect_calls_in_statement(context, init_stmt, calls);
            }
            if let Some(cond_expr) = cond {
                collect_calls_in_expr(context, cond_expr, calls);
            }
            if let Some(step_stmt) = step.as_deref() {
                collect_calls_in_statement(context, step_stmt, calls);
            }
            collect_called_functions_into(context, body, calls);
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            collect_calls_in_expr(context, map, calls);
            collect_called_functions_into(context, body, calls);
        }
        TypedStatement::MapSet { map, key, value } => {
            collect_calls_in_expr(context, map, calls);
            collect_calls_in_expr(context, key, calls);
            collect_calls_in_expr(context, value, calls);
        }
        TypedStatement::Return(None) | TypedStatement::Break | TypedStatement::Continue => {}
    }
}
fn collect_calls_in_expr(
    context: &SemanticContext,
    expr: &TypedExpr,
    calls: &mut IndexSet<String>,
) {
    match expr.kind() {
        ExprKind::Call { target: name, args }
        | ExprKind::NamedCall {
            target: name, args, ..
        } => {
            if let Some(name) = name.user_name() {
                calls.insert(name.to_owned());
            }
            for arg in evaluated_call_args(name, args) {
                collect_calls_in_expr(context, arg, calls);
            }
        }
        ExprKind::Binary { left, right, .. } => {
            collect_calls_in_expr(context, left, calls);
            collect_calls_in_expr(context, right, calls);
        }
        ExprKind::Unary { expr: inner, .. }
        | ExprKind::NumericCast { expr: inner }
        | ExprKind::NumericTryCast { expr: inner }
        | ExprKind::OptionSome { value: inner }
        | ExprKind::ResultOk { value: inner }
        | ExprKind::ResultErr { error: inner }
        | ExprKind::Propagate { value: inner } => collect_calls_in_expr(context, inner, calls),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_calls_in_expr(context, cond, calls);
            collect_calls_in_expr(context, then_expr, calls);
            collect_calls_in_expr(context, else_expr, calls);
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            collect_calls_in_expr(context, condition, calls);
            collect_called_functions_into(context, then_branch, calls);
            collect_called_functions_into(context, else_branch, calls);
        }
        ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            collect_calls_in_expr(context, value, calls);
            collect_called_functions_into(context, then_branch, calls);
            collect_called_functions_into(context, else_branch, calls);
        }
        ExprKind::Match { value, arms } => {
            collect_calls_in_expr(context, value, calls);
            for arm in arms {
                collect_called_functions_into(context, &arm.body, calls);
            }
        }
        ExprKind::Tuple(items) | ExprKind::List(items) => {
            for item in items {
                collect_calls_in_expr(context, item, calls);
            }
        }
        ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            collect_calls_in_expr(context, source, calls);
            collect_calls_in_expr(context, expression, calls);
            if let Some(condition) = condition {
                collect_calls_in_expr(context, condition, calls);
            }
        }
        ExprKind::StructLiteral { fields, .. } => {
            for (_, value) in fields {
                collect_calls_in_expr(context, value, calls);
            }
        }
        ExprKind::JsonObject(entries) => {
            for (_, value) in entries {
                collect_calls_in_expr(context, value, calls);
            }
        }
        ExprKind::JsonArray(items) => {
            for item in items {
                collect_calls_in_expr(context, item, calls);
            }
        }
        ExprKind::Member { object, .. } => collect_calls_in_expr(context, object, calls),
        ExprKind::Index { target, index } => {
            collect_calls_in_expr(context, target, calls);
            collect_calls_in_expr(context, index, calls);
        }
        ExprKind::Bool(_)
        | ExprKind::VariantCode(_)
        | ExprKind::IntLiteral(_)
        | ExprKind::DecimalLiteral { .. }
        | ExprKind::OptionNone
        | ExprKind::String(_)
        | ExprKind::Bytes(_)
        | ExprKind::Ident(_) => {}
    }
}
fn ensure_not_state_shadow(context: &SemanticContext, name: &str) -> Result<(), SemanticError> {
    if is_state_binding(context, name) {
        return Err(SemanticError {
            code: "E_STATE_SHADOWED",
            message: format!("`{name}` shadows a state declaration"),
        });
    }
    Ok(())
}
fn ensure_new_local_binding(
    context: &SemanticContext,
    name: &str,
    vars: &HashMap<String, Type>,
) -> Result<(), SemanticError> {
    ensure_not_state_shadow(context, name)?;
    if vars.contains_key(name) {
        return Err(SemanticError {
            code: "K2001",
            message: format!("local binding `{name}` duplicates or shadows an existing binding"),
        });
    }
    if context.consts.borrow().contains_key(name) {
        return Err(SemanticError {
            code: "K2001",
            message: format!("local binding `{name}` shadows a const declaration"),
        });
    }
    if context.global_declarations.borrow().contains(name) {
        return Err(SemanticError {
            code: "K2001",
            message: format!("local binding `{name}` shadows a source declaration"),
        });
    }
    Ok(())
}
fn ensure_mutable_assignment_target(
    context: &SemanticContext,
    name: &str,
    mutable_bindings: &HashSet<String>,
) -> Result<(), SemanticError> {
    if is_state_binding(context, name) || mutable_bindings.contains(name) {
        return Ok(());
    }
    Err(SemanticError {
        code: "E_IMMUTABLE_ASSIGNMENT",
        message: format!(
            "cannot assign to immutable binding `{name}`; declare a mutable local with `var`"
        ),
    })
}
fn is_state_map_expr(context: &SemanticContext, expr: &TypedExpr) -> bool {
    matches!(resolve_struct_type(&expr.ty), Type::StateMap(_, _))
        && typed_map_expr_is_state(context, expr)
}
/// Return the syntactic root name of a typed state-handle expression.
///
/// Callers must validate that the returned root belongs to the current typed
/// program; this helper deliberately carries no process-global environment.
pub fn typed_state_handle_name(expr: &TypedExpr) -> Option<String> {
    crate::session::run_with_compiler_stack(move || typed_state_handle_name_inline(expr))
        .expect("compiler must allocate the bounded stack required to inspect a state handle")
}
fn typed_state_handle_name_inline(expr: &TypedExpr) -> Option<String> {
    match expr.kind() {
        ExprKind::Ident(name) => Some(name.clone()),
        ExprKind::Member { object, field } => {
            let base = typed_state_handle_name_inline(object)?;
            let idx = field.parse::<usize>().ok()?;
            Some(format!("{base}#{idx}"))
        }
        _ => None,
    }
}
fn is_state_handle_expr(context: &SemanticContext, expr: &TypedExpr) -> bool {
    typed_state_handle_name(expr)
        .as_deref()
        .is_some_and(|name| is_state_binding(context, name.split('#').next().unwrap_or(name)))
}
fn typed_map_expr_is_state(context: &SemanticContext, expr: &TypedExpr) -> bool {
    is_state_handle_expr(context, expr)
}
fn compute_transitive_effects(
    summaries: &HashMap<String, FunctionSummary>,
) -> HashMap<String, FunctionEffects> {
    let mut effects = summaries
        .iter()
        .map(|(name, summary)| (name.clone(), summary.direct_effects))
        .collect::<HashMap<_, _>>();
    let mut changed = true;
    while changed {
        changed = false;
        for (name, summary) in summaries {
            let mut aggregate = summary.direct_effects;
            for callee in &summary.calls {
                if let Some(callee_effects) = effects.get(callee).copied() {
                    aggregate.merge_from(callee_effects);
                }
            }
            let slot = effects.entry(name.clone()).or_default();
            changed |= slot.merge_from(aggregate);
        }
    }
    effects
}
fn describe_view_violation(effect: FunctionEffects) -> &'static str {
    if effect.mutates_durable_state {
        "durable state mutation"
    } else if effect.emits_instructions {
        "instruction emission"
    } else {
        "host side effects"
    }
}
fn validate_scalar_state_initialization(
    context: &SemanticContext,
    items: &[TypedItem],
    states: &[TypedStateDecl],
) -> Result<(), SemanticError> {
    // This check is intentionally separate from `function_state_accesses`.
    // Access metadata is a may-analysis (union), whereas initialization is a
    // must-analysis (intersection across every normal control-flow exit).
    // Recheck the call graph here so this security property fails closed even
    // if a future caller invokes it without the ordinary semantic pipeline.
    validate_acyclic_function_calls(context)?;
    let required = states
        .iter()
        .filter(|state| !matches!(&state.ty, Type::StateMap(_, _)))
        .map(|state| state.name.clone())
        .collect::<IndexSet<_>>();
    if required.is_empty() {
        return Ok(());
    }
    let functions = items
        .iter()
        .map(|item| match item {
            TypedItem::Function(function) => function,
        })
        .collect::<Vec<_>>();
    let hajimari = functions
        .iter()
        .find(|function| function.modifiers.kind == FunctionKind::Hajimari)
        .ok_or_else(|| SemanticError {
            code: "E_STATE_HAJIMARI_REQUIRED",
            message: "seiyaku scalar state requires a `hajimari()`/`始まり()` declaration".into(),
        })?;
    let required_set = required.iter().cloned().collect::<HashSet<_>>();
    let summaries = compute_definite_state_write_summaries(&functions, &required_set)?;
    let initialized = summaries.get(&hajimari.name).cloned().unwrap_or_default();
    let missing = required
        .iter()
        .filter(|state| !initialized.contains(*state))
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(SemanticError {
            code: "E_STATE_HAJIMARI_INCOMPLETE",
            message: format!(
                "hajimari() must initialize every scalar state on every normal return or fallthrough path; missing: {}",
                missing.join(", ")
            ),
        })
    }
}
type DefiniteStateSet = HashSet<String>;
/// Must-analysis state for one block.
///
/// Every populated exit set is the intersection of initialized states across
/// all paths taking that exit kind. `None` means that exit is unreachable;
/// `Some(empty)` means it is reachable with no proven initialized state.
#[derive(Debug, Default)]
struct DefiniteInitFlow {
    continuing: Option<DefiniteStateSet>,
    returns: Option<DefiniteStateSet>,
    breaks: Option<DefiniteStateSet>,
    continues: Option<DefiniteStateSet>,
}
fn intersect_states(left: &mut DefiniteStateSet, right: &DefiniteStateSet) {
    left.retain(|state| right.contains(state));
}
fn merge_exit(accumulated: &mut Option<DefiniteStateSet>, candidate: Option<DefiniteStateSet>) {
    let Some(candidate) = candidate else {
        return;
    };
    if let Some(accumulated) = accumulated {
        intersect_states(accumulated, &candidate);
    } else {
        *accumulated = Some(candidate);
    }
}
fn merge_alternative_continuations(
    left: Option<DefiniteStateSet>,
    right: Option<DefiniteStateSet>,
) -> Option<DefiniteStateSet> {
    match (left, right) {
        (None, None) => None,
        (Some(state), None) | (None, Some(state)) => Some(state),
        (Some(mut left), Some(right)) => {
            intersect_states(&mut left, &right);
            Some(left)
        }
    }
}
#[derive(Debug, Default)]
struct DefiniteInitExprFlow {
    continuing: Option<DefiniteStateSet>,
    returns: Option<DefiniteStateSet>,
    breaks: Option<DefiniteStateSet>,
    continues: Option<DefiniteStateSet>,
}
fn continue_definite_init_expr(
    mut flow: DefiniteInitExprFlow,
    expr: &TypedExpr,
    required: &DefiniteStateSet,
    summaries: &HashMap<String, DefiniteStateSet>,
) -> DefiniteInitExprFlow {
    let Some(incoming) = flow.continuing.take() else {
        return flow;
    };
    let next = analyze_definite_init_expr(expr, incoming, required, summaries);
    flow.continuing = next.continuing;
    merge_exit(&mut flow.returns, next.returns);
    merge_exit(&mut flow.breaks, next.breaks);
    merge_exit(&mut flow.continues, next.continues);
    flow
}
fn merge_alternative_expr_flows(
    mut left: DefiniteInitExprFlow,
    right: DefiniteInitExprFlow,
) -> DefiniteInitExprFlow {
    left.continuing = merge_alternative_continuations(left.continuing, right.continuing);
    merge_exit(&mut left.returns, right.returns);
    merge_exit(&mut left.breaks, right.breaks);
    merge_exit(&mut left.continues, right.continues);
    left
}
fn block_expr_flow(flow: DefiniteInitFlow) -> DefiniteInitExprFlow {
    DefiniteInitExprFlow {
        continuing: flow.continuing,
        returns: flow.returns,
        breaks: flow.breaks,
        continues: flow.continues,
    }
}
fn analyze_definite_init_expr(
    expr: &TypedExpr,
    initialized: DefiniteStateSet,
    required: &DefiniteStateSet,
    summaries: &HashMap<String, DefiniteStateSet>,
) -> DefiniteInitExprFlow {
    let continuing = |state| DefiniteInitExprFlow {
        continuing: Some(state),
        ..DefiniteInitExprFlow::default()
    };
    match expr.kind() {
        ExprKind::Binary { op, left, right } => {
            let mut flow = analyze_definite_init_expr(left, initialized, required, summaries);
            if matches!(op, BinaryOp::And | BinaryOp::Or) {
                // The RHS of `&&` and `||` is conditional. A write is definite
                // only if it is already present after the always-evaluated LHS.
                let Some(after_left) = flow.continuing.take() else {
                    return flow;
                };
                let rhs =
                    analyze_definite_init_expr(right, after_left.clone(), required, summaries);
                flow.continuing = merge_alternative_continuations(Some(after_left), rhs.continuing);
                merge_exit(&mut flow.returns, rhs.returns);
                merge_exit(&mut flow.breaks, rhs.breaks);
                merge_exit(&mut flow.continues, rhs.continues);
                flow
            } else {
                continue_definite_init_expr(flow, right, required, summaries)
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            let mut flow = analyze_definite_init_expr(cond, initialized, required, summaries);
            let Some(after_cond) = flow.continuing.take() else {
                return flow;
            };
            let branches = merge_alternative_expr_flows(
                analyze_definite_init_expr(then_expr, after_cond.clone(), required, summaries),
                analyze_definite_init_expr(else_expr, after_cond, required, summaries),
            );
            flow.continuing = branches.continuing;
            merge_exit(&mut flow.returns, branches.returns);
            merge_exit(&mut flow.breaks, branches.breaks);
            merge_exit(&mut flow.continues, branches.continues);
            flow
        }
        ExprKind::If {
            condition,
            then_branch,
            else_branch,
        } => {
            let mut flow = analyze_definite_init_expr(condition, initialized, required, summaries);
            let Some(after_condition) = flow.continuing.take() else {
                return flow;
            };
            let branches = merge_alternative_expr_flows(
                block_expr_flow(analyze_definite_init_block(
                    then_branch,
                    after_condition.clone(),
                    required,
                    summaries,
                )),
                block_expr_flow(analyze_definite_init_block(
                    else_branch,
                    after_condition,
                    required,
                    summaries,
                )),
            );
            flow.continuing = branches.continuing;
            merge_exit(&mut flow.returns, branches.returns);
            merge_exit(&mut flow.breaks, branches.breaks);
            merge_exit(&mut flow.continues, branches.continues);
            flow
        }
        ExprKind::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            let mut flow = analyze_definite_init_expr(value, initialized, required, summaries);
            let Some(after_value) = flow.continuing.take() else {
                return flow;
            };
            let branches = merge_alternative_expr_flows(
                block_expr_flow(analyze_definite_init_block(
                    then_branch,
                    after_value.clone(),
                    required,
                    summaries,
                )),
                block_expr_flow(analyze_definite_init_block(
                    else_branch,
                    after_value,
                    required,
                    summaries,
                )),
            );
            flow.continuing = branches.continuing;
            merge_exit(&mut flow.returns, branches.returns);
            merge_exit(&mut flow.breaks, branches.breaks);
            merge_exit(&mut flow.continues, branches.continues);
            flow
        }
        ExprKind::Match { value, arms } => {
            let mut flow = analyze_definite_init_expr(value, initialized, required, summaries);
            let Some(after_value) = flow.continuing.take() else {
                return flow;
            };
            let mut branches = None;
            for arm in arms {
                let arm_flow = block_expr_flow(analyze_definite_init_block(
                    &arm.body,
                    after_value.clone(),
                    required,
                    summaries,
                ));
                branches = Some(match branches {
                    Some(previous) => merge_alternative_expr_flows(previous, arm_flow),
                    None => arm_flow,
                });
            }
            let branches = branches.unwrap_or_default();
            flow.continuing = branches.continuing;
            merge_exit(&mut flow.returns, branches.returns);
            merge_exit(&mut flow.breaks, branches.breaks);
            merge_exit(&mut flow.continues, branches.continues);
            flow
        }
        ExprKind::Call { target, args } | ExprKind::NamedCall { target, args, .. }
            if target.is_lazy_sum_error() =>
        {
            let mut flow = analyze_definite_init_expr(&args[0], initialized, required, summaries);
            let Some(after_receiver) = flow.continuing.take() else {
                return flow;
            };
            let failure =
                analyze_definite_init_expr(&args[1], after_receiver.clone(), required, summaries);
            flow.continuing = if target.intrinsic() == Some(CompilerIntrinsic::Expect) {
                Some(after_receiver)
            } else {
                merge_alternative_continuations(Some(after_receiver), failure.continuing)
            };
            merge_exit(&mut flow.returns, failure.returns);
            merge_exit(&mut flow.breaks, failure.breaks);
            merge_exit(&mut flow.continues, failure.continues);
            flow
        }
        ExprKind::Call { target: name, args } => {
            // Arguments are evaluated eagerly in source order. The call itself
            // contributes exactly the callee's must-write summary; unknown or
            // external bodies contribute nothing and therefore fail closed.
            let mut flow = continuing(initialized);
            for arg in args {
                flow = continue_definite_init_expr(flow, arg, required, summaries);
            }
            if let (Some(initialized), Some(callee_writes)) = (
                flow.continuing.as_mut(),
                name.user_name().and_then(|name| summaries.get(name)),
            ) {
                initialized.extend(callee_writes.iter().cloned());
            }
            flow
        }
        ExprKind::NamedCall {
            target: name,
            args,
            evaluation_order,
        } => {
            let mut flow = continuing(initialized);
            for index in evaluation_order {
                flow = continue_definite_init_expr(flow, &args[*index], required, summaries);
            }
            if let (Some(initialized), Some(callee_writes)) = (
                flow.continuing.as_mut(),
                name.user_name().and_then(|name| summaries.get(name)),
            ) {
                initialized.extend(callee_writes.iter().cloned());
            }
            flow
        }
        ExprKind::Tuple(items) | ExprKind::List(items) => {
            let mut flow = continuing(initialized);
            for item in items {
                flow = continue_definite_init_expr(flow, item, required, summaries);
            }
            flow
        }
        ExprKind::ListComprehension {
            expression,
            source,
            condition,
            ..
        } => {
            // The source is always evaluated. A bounded source may be empty,
            // so neither the filter nor result expression contributes a
            // definite write. Their early-return paths still leave the
            // enclosing function and must participate in the must-analysis.
            let mut flow = analyze_definite_init_expr(source, initialized, required, summaries);
            if let Some(after_source) = flow.continuing.clone() {
                let mut iteration = continuing(after_source);
                if let Some(condition) = condition {
                    iteration =
                        continue_definite_init_expr(iteration, condition, required, summaries);
                }
                iteration = continue_definite_init_expr(iteration, expression, required, summaries);
                merge_exit(&mut flow.returns, iteration.returns);
                merge_exit(&mut flow.breaks, iteration.breaks);
                merge_exit(&mut flow.continues, iteration.continues);
            }
            flow
        }
        ExprKind::StructLiteral { fields, .. } => {
            let mut flow = continuing(initialized);
            for (_, value) in fields {
                flow = continue_definite_init_expr(flow, value, required, summaries);
            }
            flow
        }
        ExprKind::JsonObject(entries) => {
            let mut flow = continuing(initialized);
            for (_, value) in entries {
                flow = continue_definite_init_expr(flow, value, required, summaries);
            }
            flow
        }
        ExprKind::JsonArray(items) => {
            let mut flow = continuing(initialized);
            for item in items {
                flow = continue_definite_init_expr(flow, item, required, summaries);
            }
            flow
        }
        ExprKind::Unary { expr, .. }
        | ExprKind::NumericCast { expr }
        | ExprKind::NumericTryCast { expr }
        | ExprKind::OptionSome { value: expr }
        | ExprKind::ResultOk { value: expr }
        | ExprKind::ResultErr { error: expr } => {
            analyze_definite_init_expr(expr, initialized, required, summaries)
        }
        ExprKind::Propagate { value } => {
            let mut flow = analyze_definite_init_expr(value, initialized, required, summaries);
            match value.kind() {
                // These constructors make the outcome of `?` statically
                // known, so avoid inventing an unreachable exit or
                // continuation in the must-analysis.
                ExprKind::OptionSome { .. } | ExprKind::ResultOk { .. } => {}
                ExprKind::OptionNone | ExprKind::ResultErr { .. } => {
                    let returned = flow.continuing.take();
                    merge_exit(&mut flow.returns, returned);
                }
                _ => {
                    // An inactive Option or error Result returns from the
                    // enclosing function before any following initialization.
                    // The active path continues with the same state.
                    let returned = flow.continuing.clone();
                    merge_exit(&mut flow.returns, returned);
                }
            }
            flow
        }
        ExprKind::Member { object, .. } => {
            analyze_definite_init_expr(object, initialized, required, summaries)
        }
        ExprKind::Index { target, index } => {
            let flow = analyze_definite_init_expr(target, initialized, required, summaries);
            continue_definite_init_expr(flow, index, required, summaries)
        }
        ExprKind::VariantCode(_)
        | ExprKind::IntLiteral(_)
        | ExprKind::DecimalLiteral { .. }
        | ExprKind::OptionNone
        | ExprKind::Bool(_)
        | ExprKind::String(_)
        | ExprKind::Bytes(_)
        | ExprKind::Ident(_) => continuing(initialized),
    }
}
fn analyze_definite_init_block(
    block: &TypedBlock,
    incoming: DefiniteStateSet,
    required: &DefiniteStateSet,
    summaries: &HashMap<String, DefiniteStateSet>,
) -> DefiniteInitFlow {
    let mut flow = DefiniteInitFlow {
        continuing: Some(incoming),
        ..DefiniteInitFlow::default()
    };
    for statement in &block.statements {
        let Some(incoming) = flow.continuing.take() else {
            // Statements following an unconditional control transfer are
            // unreachable and cannot establish a definite write.
            break;
        };
        let statement_flow =
            analyze_definite_init_statement(statement, incoming, required, summaries);
        flow.continuing = statement_flow.continuing;
        merge_exit(&mut flow.returns, statement_flow.returns);
        merge_exit(&mut flow.breaks, statement_flow.breaks);
        merge_exit(&mut flow.continues, statement_flow.continues);
    }
    if let Some(tail) = &block.tail
        && let Some(continuing) = flow.continuing.take()
    {
        let tail_flow = analyze_definite_init_expr(tail, continuing, required, summaries);
        flow.continuing = tail_flow.continuing;
        merge_exit(&mut flow.returns, tail_flow.returns);
        merge_exit(&mut flow.breaks, tail_flow.breaks);
        merge_exit(&mut flow.continues, tail_flow.continues);
    }
    flow
}
fn analyze_definite_init_statement(
    statement: &TypedStatement,
    incoming: DefiniteStateSet,
    required: &DefiniteStateSet,
    summaries: &HashMap<String, DefiniteStateSet>,
) -> DefiniteInitFlow {
    match statement.kind() {
        TypedStatement::Let { name, value } => {
            let mut expression_flow =
                analyze_definite_init_expr(value, incoming, required, summaries);
            let state_name = name.split('#').next().unwrap_or(name);
            if required.contains(state_name)
                && let Some(continuing) = expression_flow.continuing.as_mut()
            {
                continuing.insert(state_name.to_owned());
            }
            DefiniteInitFlow {
                continuing: expression_flow.continuing,
                returns: expression_flow.returns,
                breaks: expression_flow.breaks,
                continues: expression_flow.continues,
            }
        }
        TypedStatement::Expr(expr) => {
            let expression_flow = analyze_definite_init_expr(expr, incoming, required, summaries);
            DefiniteInitFlow {
                continuing: expression_flow.continuing,
                returns: expression_flow.returns,
                breaks: expression_flow.breaks,
                continues: expression_flow.continues,
            }
        }
        TypedStatement::Return(expr) => {
            if let Some(expr) = expr {
                let mut expression_flow =
                    analyze_definite_init_expr(expr, incoming, required, summaries);
                let returned = expression_flow.continuing.take();
                merge_exit(&mut expression_flow.returns, returned);
                DefiniteInitFlow {
                    returns: expression_flow.returns,
                    breaks: expression_flow.breaks,
                    continues: expression_flow.continues,
                    continuing: None,
                }
            } else {
                DefiniteInitFlow {
                    returns: Some(incoming),
                    ..DefiniteInitFlow::default()
                }
            }
        }
        TypedStatement::Break => DefiniteInitFlow {
            breaks: Some(incoming),
            ..DefiniteInitFlow::default()
        },
        TypedStatement::Continue => DefiniteInitFlow {
            continues: Some(incoming),
            ..DefiniteInitFlow::default()
        },
        TypedStatement::If {
            cond,
            then_branch,
            else_branch,
        } => {
            let condition_flow = analyze_definite_init_expr(cond, incoming, required, summaries);
            let Some(after_cond) = condition_flow.continuing else {
                return DefiniteInitFlow {
                    returns: condition_flow.returns,
                    breaks: condition_flow.breaks,
                    continues: condition_flow.continues,
                    continuing: None,
                };
            };
            let then_flow =
                analyze_definite_init_block(then_branch, after_cond.clone(), required, summaries);
            let else_flow = if let Some(branch) = else_branch {
                analyze_definite_init_block(branch, after_cond, required, summaries)
            } else {
                DefiniteInitFlow {
                    continuing: Some(after_cond),
                    ..DefiniteInitFlow::default()
                }
            };
            let mut flow = DefiniteInitFlow {
                continuing: merge_alternative_continuations(
                    then_flow.continuing,
                    else_flow.continuing,
                ),
                returns: condition_flow.returns,
                breaks: condition_flow.breaks,
                continues: condition_flow.continues,
            };
            merge_exit(&mut flow.returns, then_flow.returns);
            merge_exit(&mut flow.returns, else_flow.returns);
            merge_exit(&mut flow.breaks, then_flow.breaks);
            merge_exit(&mut flow.breaks, else_flow.breaks);
            merge_exit(&mut flow.continues, then_flow.continues);
            merge_exit(&mut flow.continues, else_flow.continues);
            flow
        }
        TypedStatement::IfLet {
            value,
            then_branch,
            else_branch,
            ..
        } => {
            let value_flow = analyze_definite_init_expr(value, incoming, required, summaries);
            let Some(after_value) = value_flow.continuing else {
                return DefiniteInitFlow {
                    returns: value_flow.returns,
                    breaks: value_flow.breaks,
                    continues: value_flow.continues,
                    continuing: None,
                };
            };
            let then_flow =
                analyze_definite_init_block(then_branch, after_value.clone(), required, summaries);
            let else_flow = if let Some(branch) = else_branch {
                analyze_definite_init_block(branch, after_value, required, summaries)
            } else {
                DefiniteInitFlow {
                    continuing: Some(after_value),
                    ..DefiniteInitFlow::default()
                }
            };
            let mut flow = DefiniteInitFlow {
                continuing: merge_alternative_continuations(
                    then_flow.continuing,
                    else_flow.continuing,
                ),
                returns: value_flow.returns,
                breaks: value_flow.breaks,
                continues: value_flow.continues,
            };
            merge_exit(&mut flow.returns, then_flow.returns);
            merge_exit(&mut flow.returns, else_flow.returns);
            merge_exit(&mut flow.breaks, then_flow.breaks);
            merge_exit(&mut flow.breaks, else_flow.breaks);
            merge_exit(&mut flow.continues, then_flow.continues);
            merge_exit(&mut flow.continues, else_flow.continues);
            flow
        }
        TypedStatement::While { cond, body } => {
            let condition_flow = analyze_definite_init_expr(cond, incoming, required, summaries);
            let Some(after_cond) = condition_flow.continuing else {
                return DefiniteInitFlow {
                    continuing: condition_flow.breaks,
                    returns: condition_flow.returns,
                    ..DefiniteInitFlow::default()
                };
            };
            let mut loop_flow =
                analyze_may_execute_loop(body, after_cond, None, required, summaries);
            loop_flow.continuing =
                merge_alternative_continuations(loop_flow.continuing, condition_flow.breaks);
            merge_exit(&mut loop_flow.returns, condition_flow.returns);
            loop_flow
        }
        TypedStatement::For {
            init,
            cond,
            step,
            body,
            ..
        } => {
            let mut prefix = if let Some(init) = init.as_deref() {
                analyze_definite_init_statement(init, incoming, required, summaries)
            } else {
                DefiniteInitFlow {
                    continuing: Some(incoming),
                    ..DefiniteInitFlow::default()
                }
            };
            let mut loop_exits = prefix.breaks.take();
            let Some(mut after_prefix) = prefix.continuing.take() else {
                return DefiniteInitFlow {
                    continuing: loop_exits,
                    returns: prefix.returns,
                    ..DefiniteInitFlow::default()
                };
            };
            if let Some(cond) = cond {
                // A C-style loop evaluates its condition once even when its
                // body executes zero times.
                let condition_flow =
                    analyze_definite_init_expr(cond, after_prefix, required, summaries);
                merge_exit(&mut prefix.returns, condition_flow.returns);
                loop_exits = merge_alternative_continuations(loop_exits, condition_flow.breaks);
                let Some(continuing) = condition_flow.continuing else {
                    return DefiniteInitFlow {
                        continuing: loop_exits,
                        returns: prefix.returns,
                        ..DefiniteInitFlow::default()
                    };
                };
                after_prefix = continuing;
            }
            let mut loop_flow =
                analyze_may_execute_loop(body, after_prefix, step.as_deref(), required, summaries);
            loop_flow.continuing =
                merge_alternative_continuations(loop_flow.continuing, loop_exits);
            merge_exit(&mut loop_flow.returns, prefix.returns);
            loop_flow
        }
        TypedStatement::ForEachMap { map, body, .. } => {
            let map_flow = analyze_definite_init_expr(map, incoming, required, summaries);
            let Some(after_map) = map_flow.continuing else {
                return DefiniteInitFlow {
                    continuing: map_flow.breaks,
                    returns: map_flow.returns,
                    ..DefiniteInitFlow::default()
                };
            };
            let mut loop_flow =
                analyze_may_execute_loop(body, after_map, None, required, summaries);
            loop_flow.continuing =
                merge_alternative_continuations(loop_flow.continuing, map_flow.breaks);
            merge_exit(&mut loop_flow.returns, map_flow.returns);
            loop_flow
        }
        TypedStatement::MapSet { map, key, value } => {
            // StateMap roots are deliberately excluded from `required`, but
            // calls nested in their receiver/key/value still execute eagerly.
            let flow = analyze_definite_init_expr(map, incoming, required, summaries);
            let flow = continue_definite_init_expr(flow, key, required, summaries);
            let flow = continue_definite_init_expr(flow, value, required, summaries);
            DefiniteInitFlow {
                continuing: flow.continuing,
                returns: flow.returns,
                breaks: flow.breaks,
                continues: flow.continues,
            }
        }
    }
}
fn analyze_may_execute_loop(
    body: &TypedBlock,
    before_body: DefiniteStateSet,
    step: Option<&TypedStatement>,
    required: &DefiniteStateSet,
    summaries: &HashMap<String, DefiniteStateSet>,
) -> DefiniteInitFlow {
    // Every V1 loop is treated as possibly executing zero times. Therefore no
    // body or step write can strengthen the normal post-loop state. We still
    // inspect a possible first iteration so `return` paths inside the loop are
    // included in the function's must-analysis.
    let mut body_flow = analyze_definite_init_block(body, before_body.clone(), required, summaries);
    let reaches_step =
        merge_alternative_continuations(body_flow.continuing.take(), body_flow.continues.take());
    if let (Some(step), Some(reaches_step)) = (step, reaches_step) {
        let step_flow = analyze_definite_init_statement(step, reaches_step, required, summaries);
        merge_exit(&mut body_flow.returns, step_flow.returns);
    }
    DefiniteInitFlow {
        continuing: Some(before_body),
        returns: body_flow.returns,
        // `break` exits this loop normally and cannot improve the post-loop
        // state because the zero-iteration path is always present. `continue`
        // remains inside the loop. Both are consumed here.
        breaks: None,
        continues: None,
    }
}
fn definite_writes_on_normal_exit(
    function: &TypedFunction,
    required: &DefiniteStateSet,
    summaries: &HashMap<String, DefiniteStateSet>,
) -> DefiniteStateSet {
    let mut flow =
        analyze_definite_init_block(&function.body, DefiniteStateSet::new(), required, summaries);
    merge_exit(&mut flow.returns, flow.continuing);
    // Top-level break/continue are rejected earlier. If malformed typed HIR
    // reaches this pass, intersecting with an empty set fails closed.
    if flow.breaks.is_some() || flow.continues.is_some() {
        return DefiniteStateSet::new();
    }
    flow.returns.unwrap_or_default()
}
fn compute_definite_state_write_summaries(
    functions: &[&TypedFunction],
    required: &DefiniteStateSet,
) -> Result<HashMap<String, DefiniteStateSet>, SemanticError> {
    let mut summaries = functions
        .iter()
        .map(|function| (function.name.clone(), DefiniteStateSet::new()))
        .collect::<HashMap<_, _>>();
    // The already-validated acyclic call graph has height at most N. Start at
    // the conservative empty summary and iterate to the least fixed point, so
    // calls through arbitrarily ordered helpers are source-order independent.
    for _ in 0..=functions.len() {
        let next = functions
            .iter()
            .map(|function| {
                (
                    function.name.clone(),
                    definite_writes_on_normal_exit(function, required, &summaries),
                )
            })
            .collect::<HashMap<_, _>>();
        if next == summaries {
            return Ok(next);
        }
        summaries = next;
    }
    Err(SemanticError {
        code: "E_STATE_HAJIMARI_INCOMPLETE",
        message: "compiler could not prove complete scalar-state assignment by `hajimari`/`始まり` through the helper call graph"
            .into(),
    })
}

#[cfg(test)]
use kotodama_surface::source_policy::{
    V1_FORBIDDEN_SOURCE_IDENTIFIERS, V1_RETIRED_NUMERIC_TYPE_NAMES,
};
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_test_fragment as parse;

    #[test]
    fn trigger_metadata_integer_domain_is_exact_through_u128() {
        for raw in [
            "18446744073709551616",
            "340282366920938463463374607431768211455",
        ] {
            let value = raw.parse().expect("integer fits the Kotodama int domain");
            let json = json_from_expr(&Expr::IntLiteral(value))
                .expect("unsigned 128-bit metadata integer must lower exactly");
            assert_eq!(json.to_string(), raw);
        }

        let above_max = "340282366920938463463374607431768211456"
            .parse()
            .expect("u128::MAX + 1 fits the Kotodama int domain");
        let error = json_from_expr(&Expr::IntLiteral(above_max))
            .expect_err("metadata integers above u128 must be rejected");
        assert_eq!(error.code, "E_TRIGGER_METADATA_VALUE");
    }

    #[test]
    fn typed_aggregate_traits_are_spawn_free_for_flat_width() {
        let expressions: Vec<_> = (0..16_384)
            .map(|_| TypedExpr {
                expr: ExprKind::IntLiteral(BigInt::one()),
                ty: Type::Int,
            })
            .collect();

        crate::session::reset_compiler_worker_spawn_count();
        let cloned_expressions = expressions.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(expressions, cloned_expressions);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        drop(cloned_expressions);

        let statements: Vec<_> = expressions.into_iter().map(TypedStatement::Expr).collect();
        crate::session::reset_compiler_worker_spawn_count();
        let cloned_statements = statements.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(statements, cloned_statements);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        drop(cloned_statements);

        let function = TypedFunction {
            name: "wide".to_owned(),
            params: Vec::new(),
            param_types: Vec::new(),
            body: TypedBlock::new(statements, None),
            ret_ty: None,
            modifiers: FunctionModifiers::default(),
            location: SourceLocation { line: 1, column: 1 },
            source: None,
            name_source: None,
        };

        crate::session::reset_compiler_worker_spawn_count();
        let cloned_function = function.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(function, cloned_function);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        drop(cloned_function);

        let items = vec![TypedItem::Function(function)];
        crate::session::reset_compiler_worker_spawn_count();
        let cloned_items = items.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(items, cloned_items);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        drop(cloned_items);

        let program = TypedProgram {
            permissions: Vec::new(),
            unit: SourceUnit {
                kind: SourceUnitKind::Module,
                name: "Wide".to_owned(),
            },
            items,
            states: Vec::new(),
            error_types: Vec::new(),
            enum_types: Vec::new(),
            events: Vec::new(),
            error_messages: Vec::new(),
            triggers: Vec::new(),
            message_entries: Vec::new(),
            hir_nodes: BTreeMap::new(),
            source_files: BTreeMap::new(),
            test_support_enabled: false,
        };
        crate::session::reset_compiler_worker_spawn_count();
        let cloned_program = program.clone();
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);

        crate::session::reset_compiler_worker_spawn_count();
        assert_eq!(program, cloned_program);
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
        drop(cloned_program);

        crate::session::reset_compiler_worker_spawn_count();
        assert!(format!("{program:?}").contains("TypedProgram"));
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
    }

    #[test]
    fn semantic_type_and_expression_traits_are_iterative_at_the_depth_boundary() {
        let mut ty = Type::Int;
        for _ in 0..crate::source::MAX_NESTING_DEPTH {
            ty = Type::Option(Box::new(ty));
        }

        let mut expression = TypedExpr {
            expr: ExprKind::IntLiteral(BigInt::one()),
            ty: Type::Int,
        };
        for _ in 0..crate::source::MAX_NESTING_DEPTH {
            expression = TypedExpr {
                expr: ExprKind::If {
                    condition: Box::new(TypedExpr {
                        expr: ExprKind::Bool(true),
                        ty: Type::Bool,
                    }),
                    then_branch: TypedBlock::new(vec![TypedStatement::Expr(expression)], None),
                    else_branch: TypedBlock::new(
                        Vec::new(),
                        Some(Box::new(TypedExpr {
                            expr: ExprKind::IntLiteral(BigInt::zero()),
                            ty: Type::Int,
                        })),
                    ),
                },
                ty: Type::Unit,
            };
        }

        crate::session::reset_compiler_worker_spawn_count();
        let (cloned_type, cloned_expression) = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("kotodama-small-typed-traits".to_owned())
                .stack_size(128 * 1024)
                .spawn_scoped(scope, || {
                    let cloned_type = ty.clone();
                    assert_eq!(ty, cloned_type);
                    let cloned_expression = expression.clone();
                    assert_eq!(expression, cloned_expression);
                    (cloned_type, cloned_expression)
                })
                .expect("spawn small typed-trait caller")
                .join()
                .expect("typed traits must not consume the caller stack")
        });
        assert_eq!(ty, cloned_type);
        assert_eq!(expression, cloned_expression);
        assert!(format!("{ty:?}").starts_with("Option<"));
        assert!(format!("{:?}", expression.expr).starts_with("If("));
        assert_eq!(crate::session::compiler_worker_spawn_count(), 0);
    }

    #[test]
    fn public_semantic_apis_handoff_from_a_small_caller() {
        let depth = crate::source::MAX_NESTING_DEPTH - 2;
        let expression = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let source =
            format!("module StackMargin {{ fn value() {{ let nested = {expression}; }} }}");
        std::thread::Builder::new()
            .name("kotodama-small-semantic-caller".to_owned())
            .stack_size(128 * 1024)
            .spawn(move || {
                let program = crate::parser::parse(&source)
                    .expect("boundary-depth semantic fixture must parse");
                let context = SemanticContext::new();
                let signatures = context
                    .resolve_function_signatures(&program)
                    .expect("boundary-depth signature resolution must use the compiler worker");
                assert!(signatures.contains_key("value"));
                let typed = context
                    .analyze(&program)
                    .expect("boundary-depth semantic analysis must use the compiler worker");
                assert_eq!(typed.unit.name, "StackMargin");
                let typed_clone = typed.clone();
                assert_eq!(typed, typed_clone);
                drop(typed_clone);
                assert!(format!("{typed:?}").contains("TypedProgram"));
                validate_linked_program(&typed, false)
                    .expect("linked validation must use the compiler worker");
                let TypedItem::Function(function) = &typed.items[0];
                let TypedStatement::Let { value, .. } = function.body.statements[0].kind() else {
                    panic!("boundary fixture must retain its nested binding");
                };
                let value_clone = value.clone();
                assert_eq!(value, &value_clone);
                drop(value_clone);
                assert!(!format!("{value:?}").is_empty());
                let type_clone = value.ty.clone();
                assert_eq!(value.ty, type_clone);
                drop(type_clone);
                assert!(!format!("{:?}", value.ty).is_empty());
                let rendered = render_type_name(&value.ty);
                assert!(rendered.starts_with("List<"));
                assert!(!is_pointer_type(&value.ty));
                let (reads, writes) = function_state_accesses(function, &typed.states);
                assert!(reads.is_empty());
                assert!(writes.is_empty());
                drop(typed);
                drop(program);
            })
            .expect("spawn small semantic caller")
            .join()
            .expect("public semantic APIs must not consume the caller stack");
    }

    macro_rules! analyze_ok_tests {
        ($($name:ident: $source:expr => $parse_message:expr, $analysis_message:expr;)+) => {
            $(#[test] fn $name() { let program = parse($source).expect($parse_message); analyze(&program).expect($analysis_message); })+
        };
    }
    macro_rules! analyze_test_ok_tests {
        ($($name:ident: $source:expr => $parse_message:expr, $analysis_message:expr;)+) => {
            $(#[test] fn $name() { let program = parse($source).expect($parse_message); analyze_test(&program).expect($analysis_message); })+
        };
    }
    macro_rules! analyze_reject_code_tests {
        ($($name:ident: $source:expr => $parse_message:expr, $error:ident = $reject_message:expr, $code:expr;)+) => {
            $(#[test] fn $name() { let program = parse($source).expect($parse_message); let $error = analyze(&program).expect_err($reject_message); assert_eq!($error.code, $code); })+
        };
    }
    macro_rules! analyze_reject_contains_tests {
        ($($name:ident: $source:expr => $parse_message:expr, $error:ident = $reject_message:expr, $fragment:expr;)+) => {
            $(#[test] fn $name() { let program = parse($source).expect($parse_message); let $error = analyze(&program).expect_err($reject_message); assert!($error.message.contains($fragment)); })+
        };
    }
    macro_rules! analyze_test_reject_contains_tests {
        ($($name:ident: $source:expr => $parse_message:expr, $error:ident = $reject_message:expr, $fragment:expr;)+) => {
            $(#[test] fn $name() { let program = parse($source).expect($parse_message); let $error = analyze_test(&program).expect_err($reject_message); assert!($error.message.contains($fragment)); })+
        };
    }
    macro_rules! analyze_reject_contains_diagnostic_tests {
        ($($name:ident: $source:expr => $parse_message:expr, $error:ident = $reject_message:expr, $fragment:expr, $diagnostic:expr;)+) => {
            $(#[test] fn $name() { let program = parse($source).expect($parse_message); let $error = analyze(&program).expect_err($reject_message); assert!($error.message.contains($fragment), $diagnostic, $error.message); })+
        };
    }
    macro_rules! analyze_error_code_message_tests {
        ($($name:ident: $error:ident = $source:expr => $code:expr, $message:expr;)+) => {
            $(#[test] fn $name() { let $error = analyze_error($source); assert_eq!($error.code, $code); assert_eq!($error.message, $message); })+
        };
    }
    macro_rules! analyze_error_code_cases {
        ($name:ident: $($error:ident = $source:expr => $code:expr;)+) => {
            #[test]
            fn $name() {
                $(let $error = analyze_error($source); assert_eq!($error.code, $code);)+
            }
        };
    }
    fn shared_struct_dag_source(levels: usize, repeated_reads: usize) -> String {
        let mut source = String::from("seiyaku SharedTypes {\n");
        for index in 0..levels {
            source.push_str(&format!(
                "struct S{index:03} {{ S{:03} left; S{:03} right; }}\n",
                index + 1,
                index + 1
            ));
        }
        source.push_str(&format!("struct S{levels:03} {{ int value; }}\n"));
        source.push_str("state StateMap<int, S000> records;\nfn repeated_reads() {\n");
        for index in 0..repeated_reads {
            source.push_str(&format!("let value{index} = records.get(0);\n"));
        }
        source.push_str("}\n}\n");
        source
    }
    #[test]
    fn large_shared_struct_references_and_expression_checks_reuse_one_canonical_dag() {
        let source = shared_struct_dag_source(14, 128);
        let program = parse(&source).expect("parse repeated large-struct references");
        let context = SemanticContext::new();
        let typed = context
            .analyze(&program)
            .expect("canonical struct references must not multiply expanded work");
        let canonical = context.resolved_named_types.borrow();
        let Type::Struct {
            fields: canonical_fields,
            ..
        } = canonical.get("S000").expect("canonical root struct")
        else {
            panic!("S000 must resolve to a canonical product type");
        };
        let Type::StateMap(_, state_value) = &typed.states[0].ty else {
            panic!("fixture state must remain a StateMap");
        };
        let Type::Struct {
            fields: state_fields,
            ..
        } = state_value.as_ref()
        else {
            panic!("StateMap value must resolve to S000");
        };
        assert!(Arc::ptr_eq(canonical_fields, state_fields));
        let function = typed
            .items
            .iter()
            .find_map(|item| {
                let TypedItem::Function(function) = item;
                (function.name == "repeated_reads").then_some(function)
            })
            .expect("typed repeated-read function");
        let mut checked = 0_usize;
        for statement in &function.body.statements {
            let TypedStatement::Let { value, .. } = statement else {
                continue;
            };
            let Type::Option(value) = &value.ty else {
                continue;
            };
            let Type::Struct { fields, .. } = value.as_ref() else {
                continue;
            };
            assert!(Arc::ptr_eq(canonical_fields, fields));
            checked += 1;
        }
        assert_eq!(checked, 128);
    }
    #[test]
    fn runtime_word_count_stops_at_the_call_table_limit_for_shared_dags() {
        let source = shared_struct_dag_source(14, 0);
        let program = parse(&source).expect("parse shared word-count fixture");
        let context = SemanticContext::new();
        context
            .analyze(&program)
            .expect("shared word-count fixture must type-check");
        let canonical = context.resolved_named_types.borrow();
        let root = canonical.get("S000").expect("canonical shared root");
        assert_eq!(
            runtime_value_word_count_bounded(root, crate::regalloc::MAX_ARGUMENT_VALUES),
            Some(crate::regalloc::MAX_ARGUMENT_VALUES + 1),
            "word accounting must stop immediately after crossing the V1 call-table limit"
        );
    }
    #[test]
    fn modest_shared_struct_references_preserve_ordinary_semantics() {
        let source = shared_struct_dag_source(8, 16);
        let program = parse(&source).expect("parse modest shared references");
        let typed = analyze(&program).expect("modest shared references must type-check");
        assert_eq!(typed.states.len(), 1);
        assert!(matches!(typed.states[0].ty, Type::StateMap(_, _)));
    }
    #[test]
    fn exact_amount_is_globally_retired_while_other_numeric_names_are_contextual() {
        const EXPECTED: &[&str] = &[
            "i8",
            "i16",
            "i32",
            "i64",
            "i128",
            "isize",
            "u8",
            "u16",
            "u32",
            "u64",
            "u128",
            "usize",
            "num",
            "Int",
            "Integer",
            "float",
            "f32",
            "f64",
            "Decimal",
            "Fixed",
            "FixedPoint",
            "Amount",
            "amount",
            "money",
            "Quantity",
            "number",
        ];
        assert_eq!(V1_RETIRED_NUMERIC_TYPE_NAMES, EXPECTED);
        assert_eq!(V1_FORBIDDEN_SOURCE_IDENTIFIERS, &["Amount"]);
        for name in EXPECTED {
            assert!(
                is_reserved_source_type_declaration(name),
                "retired numeric type `{name}` must remain reserved for declared types"
            );
            let globally_forbidden = *name == "Amount";
            assert_eq!(
                is_reserved_source_declaration(name, false),
                globally_forbidden,
                "unexpected value-namespace policy for retired numeric type `{name}`"
            );
            assert_eq!(
                is_reserved_source_declaration(name, true),
                globally_forbidden,
                "unexpected function-namespace policy for retired numeric type `{name}`"
            );
        }
    }
    #[test]
    fn retired_numeric_spellings_are_rejected_as_source_unit_identities() {
        let program = parse("module i64 { fn run() {} }")
            .expect("contextual retired source-unit identity parses");
        let error = analyze(&program)
            .expect_err("retired numeric spelling must not identify a source unit");
        assert_eq!(error.code, "E_RESERVED_DECLARATION");
        assert_eq!(
            error.message,
            "source unit `i64` uses a compiler-reserved name"
        );
    }
    #[test]
    fn builtin_nominal_namespace_cannot_be_declared_as_a_source_unit() {
        for source in [
            "seiyaku kotodama { struct Payload { int value; } }",
            "module kotodama { enum Status { Active = 1 } }",
            "module kotodama { error enum Failure { Missing = 1 } }",
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, "E_RESERVED_DECLARATION", "{source}");
            assert!(error.message.contains("source unit `kotodama`"));
        }
    }

    #[test]
    fn root_struct_identities_are_nominal_and_test_environments_preserve_them() {
        let context = SemanticContext::new();
        let first = parse("seiyaku First { struct Payload { int value; } view fn echo(Payload value) authorize(anyone) -> Payload { value } }").unwrap();
        let typed = context.analyze(&first).unwrap();
        let environment = context.test_target_environment(BTreeMap::new(), IndexMap::new());
        let expected = environment.types.get("Payload").unwrap();
        assert!(matches!(expected, Type::Struct { name, .. } if name == "First::Payload"));
        let TypedItem::Function(function) = &typed.items[0];
        assert_eq!(function.ret_ty.as_ref(), Some(expected));
        let second = parse("seiyaku Second { struct Payload { int value; } view fn echo(Payload value) authorize(anyone) -> Payload { value } }").unwrap();
        let second = analyze(&second).unwrap();
        let TypedItem::Function(other) = &second.items[0];
        assert_ne!(function.ret_ty, other.ret_ty);
    }

    #[test]
    fn production_projection_accepts_registered_intrinsics_and_rejects_fabricated_calls() {
        let retained = HashSet::new();
        let removed = HashSet::new();
        let registered = [
            CompilerIntrinsic::ContractAt,
            CompilerIntrinsic::StateMapGet,
            CompilerIntrinsic::ListLen,
            CompilerIntrinsic::ListGet,
            CompilerIntrinsic::ListTrySet,
            CompilerIntrinsic::ListTryPush,
            CompilerIntrinsic::ListPop,
            CompilerIntrinsic::ListContains,
            CompilerIntrinsic::ListTake,
            CompilerIntrinsic::ListEnumerate,
            CompilerIntrinsic::ListWiden,
            CompilerIntrinsic::DecimalDivRound,
            CompilerIntrinsic::QuantityDivRound,
            CompilerIntrinsic::QuantityRatioRound,
            CompilerIntrinsic::DecimalToIntTrunc,
            CompilerIntrinsic::DecimalToIntRound,
            CompilerIntrinsic::IsSome,
            CompilerIntrinsic::IsNone,
            CompilerIntrinsic::IsOk,
            CompilerIntrinsic::IsErr,
            CompilerIntrinsic::UnwrapOr,
            CompilerIntrinsic::UnwrapErrOr,
            CompilerIntrinsic::Expect,
            CompilerIntrinsic::OptionOkOr,
            CompilerIntrinsic::ResultOrErr,
        ];
        for intrinsic in registered {
            let name = intrinsic.name();
            let expression = TypedExpr {
                expr: ExprKind::Call {
                    target: CallTarget::Intrinsic(intrinsic),
                    args: Vec::new(),
                },
                ty: Type::Int,
            };
            validate_production_projection_expr(
                &expression,
                "retained_helper",
                &retained,
                &removed,
                false,
            )
            .unwrap_or_else(|error| panic!("registered intrinsic {name} was rejected: {error:?}"));
        }
        let fabricated = TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::User("__fabricated_projection_escape".into()),
                args: Vec::new(),
            },
            ty: Type::Int,
        };
        assert!(!is_reserved_source_declaration(
            "__fabricated_projection_escape",
            true
        ));
        let error = validate_production_projection_expr(
            &fabricated,
            "retained_helper",
            &retained,
            &removed,
            false,
        )
        .expect_err("unregistered typed calls must fail closed");
        assert_eq!(error.code, "K2002");
        assert!(error.message.contains("__fabricated_projection_escape"));
    }
    #[test]
    fn removed_test_function_cannot_hide_behind_an_intrinsic_name() {
        let retained = HashSet::new();
        let removed = HashSet::from(["is_some".to_owned()]);
        let expression = TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::User("is_some".into()),
                args: Vec::new(),
            },
            ty: Type::Bool,
        };
        let error = validate_production_projection_expr(
            &expression,
            "retained_helper",
            &retained,
            &removed,
            false,
        )
        .expect_err("removed test calls must take precedence over intrinsic classification");
        assert_eq!(error.code, "E_TEST_ONLY_PRODUCTION");
        assert!(
            error
                .message
                .starts_with("`retained_helper` belongs to the deployable seiyaku"),
            "{}",
            error.message
        );
        let test_builtin = TypedExpr {
            expr: ExprKind::Call {
                target: CallTarget::Builtin(Builtin::Assert),
                args: Vec::new(),
            },
            ty: Type::Unit,
        };
        let error = validate_production_projection_expr(
            &test_builtin,
            "retained_helper",
            &retained,
            &removed,
            false,
        )
        .expect_err("deployable helpers cannot call test builtins");
        assert_eq!(error.code, "E_TEST_ONLY_PRODUCTION");
        assert!(
            error.message.contains("test-only builtin `test::assert`")
                && error
                    .message
                    .ends_with("move the helper into a `*.test.ko` module"),
            "{}",
            error.message
        );
    }
    #[test]
    fn pending_diagnostic_fills_first_spanless_failure_without_masking_structured_failure() {
        let source = crate::source::SourceId(9);
        let structured = crate::semantic_diagnostics::SemanticDiagnostic::at(
            crate::source::SourceRange::new(source, crate::source::TextRange::new(1, 2)),
            None,
        );
        let pending = crate::semantic_diagnostics::SemanticDiagnostic::at(
            crate::source::SourceRange::new(source, crate::source::TextRange::new(3, 4)),
            None,
        );
        let failure = |code, diagnostic| SemanticFailure {
            error: SemanticError {
                code,
                message: "localized text".to_owned(),
            },
            location: None,
            diagnostic,
        };
        let mut failures = SemanticFailures {
            failures: vec![
                failure("E_FIRST", Some(structured.clone())),
                failure("E_SECOND", None),
                failure("E_THIRD", None),
            ],
        };
        attach_pending_diagnostic(&mut failures, Some(pending.clone()));
        assert_eq!(failures.failures[0].diagnostic, Some(structured));
        assert_eq!(failures.failures[1].diagnostic, Some(pending));
        assert!(failures.failures[2].diagnostic.is_none());
    }
    fn sample_account_literal() -> String {
        iroha_data_model::account::AccountId::new(
            "ed0120A98BAFB0663CE08D75EBD506FEC38A84E576A7C9B0897693ED4B04FD9EF2D18D"
                .parse()
                .expect("public key"),
        )
        .to_string()
    }
    fn analyze_test(program: &Program) -> Result<TypedProgram, SemanticError> {
        SemanticContext::with_capabilities(false, true).analyze(program)
    }
    fn analyze_error(source: &str) -> SemanticError {
        let program = parse(source).expect("source should parse");
        analyze(&program).expect_err("semantic analysis should reject source")
    }
    fn returned_expr(source: &str) -> TypedExpr {
        let program = parse(source).expect("source should parse");
        let typed = analyze(&program).expect("source should analyze");
        typed
            .items
            .into_iter()
            .find_map(|item| {
                let TypedItem::Function(function) = item;
                function.body.statements.into_iter().find_map(|statement| {
                    if let TypedStatement::Return(Some(expr)) = statement {
                        Some(expr)
                    } else {
                        None
                    }
                })
            })
            .expect("function return expression")
    }
    fn function_tail(source: &str) -> TypedExpr {
        let program = parse(source).expect("source should parse");
        let typed = analyze(&program).expect("source should analyze");
        let TypedItem::Function(function) = typed.items.into_iter().next().expect("function item");
        *function.body.tail.expect("function tail expression")
    }
    #[test]
    fn ordinary_enum_values_are_nominal_exhaustive_and_not_rejection_catalogues() {
        let source = r#"module Data {
            enum Status { Active = 1, Paused = 2 }
            error enum Failure { Missing = 3 }
            fn selected(Status value) -> bool { value == Status::Active }
            fn label(Status value) -> int { match value { Status::Active => 1, Status::Paused => 2 } }
            fn branch(Status value) -> int { if let Status::Active = value { 1 } else { 2 } }
            fn pending() -> Result<int, Status> { Result::err(Status::Paused) }
            fn arrays() -> List<Status, 2> { [Status::Active, Status::Paused] }
            fn json_value(Status value) -> Json { json { status: value } }
        }"#;
        let typed =
            analyze(&parse(source).expect("data enum source")).expect("ordinary enum values");
        assert!(
            typed
                .error_types
                .iter()
                .all(|descriptor| !descriptor.identity.ends_with("::Status"))
        );
        assert!(
            typed
                .error_types
                .iter()
                .any(|descriptor| descriptor.identity.ends_with("::Failure"))
        );
        assert!(typed.error_messages.is_empty());
        let cloned = typed.clone();
        assert_eq!(
            typed, cloned,
            "typed trait walkers retain ordinary nominal identity"
        );
    }
    #[test]
    fn ordinary_enum_inventory_has_a_single_canonical_resource_bound() {
        let declarations = (0..257)
            .map(|index| format!("enum E{index:03} {{ Active = 1 }}"))
            .collect::<Vec<_>>();
        let accepted = format!("module Data {{ {} }}", declarations[..256].join(" "));
        assert_eq!(
            analyze(&parse(&accepted).unwrap())
                .unwrap()
                .enum_types
                .len(),
            256
        );
        let rejected = format!("module Data {{ {} }}", declarations.join(" "));
        assert_eq!(analyze_error(&rejected).code, "E_ENUM_SCHEMA");
    }
    #[test]
    fn ordinary_enum_patterns_and_rejection_boundaries_are_strict() {
        for (body, expected) in [
            (
                "fn f(Status value) -> int { match value { Status::Active => 1 } }",
                "E_MATCH_NON_EXHAUSTIVE",
            ),
            (
                "fn f(Status value) -> int { match value { Status::Active => 1, Status::Active => 2, Status::Paused => 3 } }",
                "E_MATCH_DUPLICATE_PATTERN",
            ),
            (
                "fn f(Status value) -> int { match value { Other::Active => 1, Status::Paused => 2 } }",
                "E_PATTERN_FAMILY",
            ),
            (
                "fn f() { let Status value = Other::Active; }",
                "E_TYPE_ANNOTATION_MISMATCH",
            ),
            ("fn f() { require(true, Status::Active); }", "K2003"),
            (
                "fn f(Option<int> value) -> int { value.expect(Status::Active) }",
                "K2003",
            ),
        ] {
            let source = format!(
                "module Data {{ enum Status {{ Active = 1, Paused = 2 }} enum Other {{ Active = 1 }} {body} }}"
            );
            let error = analyze_error(&source);
            assert_eq!(error.code, expected, "{body}: {error:?}");
        }
        assert!(parse("module Data { enum Status { Active = 1 } fn f(Status value) -> int { match value { _ => 1 } } }").is_err());
    }
    #[test]
    fn list_literals_infer_exact_or_contextual_capacity() {
        let exact = function_tail("fn exact() -> List<int, 2> { [1, 2] }");
        assert_eq!(exact.ty, Type::List(Box::new(Type::Int), 2));
        assert!(matches!(exact.expr, ExprKind::List(ref items) if items.len() == 2));
        let contextual = function_tail("fn wider() -> List<int, 8> { [1, 2] }");
        assert_eq!(contextual.ty, Type::List(Box::new(Type::Int), 8));
        let inferred_program =
            parse("fn inferred() { let values = [1, 2, 3]; }").expect("parse inferred List");
        let inferred = analyze(&inferred_program).expect("analyze inferred List");
        let TypedItem::Function(function) = &inferred.items[0];
        let TypedStatement::Let { value, .. } = &function.body.statements[0] else {
            panic!("expected List binding");
        };
        assert_eq!(value.ty, Type::List(Box::new(Type::Int), 3));
    }
    #[test]
    fn empty_and_oversized_list_literals_fail_closed() {
        let empty = function_tail("fn empty() -> List<int, 4> { [] }");
        assert_eq!(empty.ty, Type::List(Box::new(Type::Int), 4));
        let error = analyze_error("fn missing_context() { let values = []; }");
        assert_eq!(error.code, "E_LIST_EMPTY_CONTEXT");
        let values = std::iter::repeat_n("1", 65).collect::<Vec<_>>().join(", ");
        let error = analyze_error(&format!("fn oversized() {{ let values = [{values}]; }}"));
        assert_eq!(error.code, "E_LIST_CAPACITY");
    }
    #[test]
    fn empty_product_list_elements_have_one_unit_word_at_every_semantic_boundary() {
        for source in [
            "struct Empty {} fn typed() -> List<Empty, 1> { [Empty {}] }",
            "struct Empty {} fn inferred() { let values = [Empty {}]; }",
            "struct Empty {} fn contextual() { let List<Empty, 2> values = []; }",
            "struct Empty {} struct Pair { Empty left, Empty right } fn parameter(List<Pair, 1> values) { let _values = values; }",
            "struct Empty {} fn nested(Option<List<Empty, 1>> value) { let _value = value; }",
            "struct Empty {} struct Holder { List<Empty, 1> invalid } fn unused() { return; }",
            "struct Empty {} fn comprehension() { let source = [1]; let values = [Empty {} for item in source]; }",
        ] {
            let program = parse(source).expect("parse empty-product list");
            analyze(&program).unwrap_or_else(|error| panic!("{source}: {error}"));
        }
    }
    #[test]
    fn contextual_empty_lists_and_one_word_sum_handles_remain_valid() {
        let ordinary = function_tail("fn empty() -> List<int, 4> { [] }");
        assert_eq!(ordinary.ty, Type::List(Box::new(Type::Int), 4));
        let sum_handle = function_tail(
            "struct Empty {} fn values() -> List<Option<Empty>, 1> { [Option::none] }",
        );
        assert_eq!(
            sum_handle.ty,
            Type::List(
                Box::new(Type::Option(Box::new(Type::Struct {
                    name: "TestContract::Empty".into(),
                    fields: Arc::from(Vec::new()),
                }))),
                1,
            )
        );
        let forward = function_tail(
            "struct Holder { List<Value, 1> values } struct Value { int item } fn values() -> List<Value, 1> { [Value { item: 1 }] }",
        );
        assert!(matches!(forward.ty, Type::List(_, 1)));
    }
    #[test]
    fn native_json_rejects_decoded_duplicate_keys_and_oversized_nodes() {
        let error = analyze_error(include_str!(
            "semantic/test_sources/native_json_rejects_decoded_duplicate_keys_and_oversized_nodes_1.ko"
        ));
        assert_eq!(error.code, "E_JSON_DUPLICATE_KEY");
        let object_entries = (0..65)
            .map(|index| format!("key{index}: {index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let error = analyze_error(&format!(
            "fn oversized_object() -> Json {{ json {{ {object_entries} }} }}"
        ));
        assert_eq!(error.code, "E_JSON_CAPACITY");
        let array_elements = (0..65)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let error = analyze_error(&format!(
            "fn oversized_array() -> Json {{ json [{array_elements}] }}"
        ));
        assert_eq!(error.code, "E_JSON_CAPACITY");
    }
    #[test]
    fn json_parse_literals_fail_during_semantic_analysis() {
        let duplicate = analyze_error(include_str!(
            "semantic/test_sources/json_parse_literals_fail_during_semantic_analysis_1.ko"
        ));
        assert_eq!(duplicate.code, "E_JSON_DUPLICATE_KEY");
        assert!(duplicate.message.contains("owner"), "{}", duplicate.message);
        let malformed = analyze_error(include_str!(
            "semantic/test_sources/json_parse_literals_fail_during_semantic_analysis_2.ko"
        ));
        assert_eq!(malformed.code, "E_JSON_LITERAL_INVALID");
        assert!(
            malformed.message.contains("Json::parse"),
            "{}",
            malformed.message
        );
    }
    #[test]
    fn json_parse_requires_a_direct_literal_but_native_json_remains_typed() {
        for source in [
            include_str!(
                "semantic/test_sources/json_parse_requires_a_direct_literal_but_native_json_remains_typed_1.ko"
            ),
            include_str!(
                "semantic/test_sources/json_parse_requires_a_direct_literal_but_native_json_remains_typed_2.ko"
            ),
            include_str!(
                "semantic/test_sources/json_parse_requires_a_direct_literal_but_native_json_remains_typed_3.ko"
            ),
        ] {
            let dynamic = analyze_error(source);
            assert_eq!(dynamic.code, "E_JSON_LITERAL_REQUIRED", "{source}");
            assert_eq!(dynamic.message, JSON_LITERAL_REQUIRED_MESSAGE, "{source}");
        }
        let native = parse(
            include_str!("semantic/test_sources/json_parse_requires_a_direct_literal_but_native_json_remains_typed_4.ko"),
        )
        .expect("lowercase typed native JSON source should parse");
        analyze(&native).expect("lowercase typed native JSON must remain available");
    }
    #[test]
    fn native_json_requires_explicit_result_and_struct_conversion() {
        let result =
            analyze_error("fn invalid(Result<int, int> value) -> Json { json { value: value } }");
        assert_eq!(result.code, "E_JSON_VALUE_TYPE");
        assert!(result.message.contains("Result"), "{}", result.message);
        let structure = analyze_error(
            "struct Payload { int value } fn invalid(Payload value) -> Json { json { value: value } }",
        );
        assert_eq!(structure.code, "E_JSON_VALUE_TYPE");
        assert!(
            structure.message.contains("arbitrary struct"),
            "{}",
            structure.message
        );
    }
    #[test]
    fn native_json_rejects_recursive_schema_limits_during_semantic_checking() {
        let children = std::iter::repeat_n("json [1, 2, 3, 4]", 64)
            .collect::<Vec<_>>()
            .join(", ");
        let expression = format!("json [{children}]");
        let error = analyze_error(&format!(
            "fn recursively_oversized() -> Json {{ {expression} }}"
        ));
        assert_eq!(error.code, "E_JSON_SCHEMA_LIMIT", "{}", error.message);
        assert!(error.message.contains("V1"));
        let long_keys = (0..64)
            .map(|index| format!("\"key{index}{}\": {index}", "x".repeat(1_100)))
            .collect::<Vec<_>>()
            .join(", ");
        let error = analyze_error(&format!(
            "fn byte_oversized() -> Json {{ json {{ {long_keys} }} }}"
        ));
        assert_eq!(error.code, "E_JSON_SCHEMA_LIMIT", "{}", error.message);
        assert!(error.message.contains("byte limit"), "{}", error.message);
    }
    #[test]
    fn list_comprehensions_preserve_the_proven_source_maximum() {
        let expression = function_tail(
            "fn doubled() -> List<int, 8> { let List<int, 8> source = [1, 2]; [value * 2 for value in source if value > 0] }",
        );
        assert_eq!(expression.ty, Type::List(Box::new(Type::Int), 8));
        assert!(matches!(
            expression.expr,
            ExprKind::ListComprehension { .. }
        ));
        let error = analyze_error(
            "fn too_small() -> List<int, 4> { let List<int, 8> source = [1, 2]; [value for value in source if false] }",
        );
        assert_eq!(error.code, "E_LIST_COMPREHENSION_CAPACITY");
        assert!(error.message.contains("filters do not reduce"));
    }
    #[test]
    fn lists_allow_nested_structures_but_reject_resource_handles() {
        let nested = function_tail(
            "struct Pair { int left, bool right } fn nested() -> List<List<Pair, 2>, 2> { [[Pair { left: 1, right: true }]] }",
        );
        assert!(matches!(nested.ty, Type::List(_, 2)));
        let error =
            analyze_error("fn resources(List<Option<StateMap<int, int>>, 2> value) { return; }");
        assert_eq!(error.code, "E_LIST_RESOURCE_ELEMENT");
        let secret_source =
            "fn resources(List<Option<Secret<int>>, 2> value) { let ignored = value; }";
        let secret_program = parse(secret_source).expect("secret List source should parse");
        let error = SemanticContext::with_zk_enabled(true)
            .analyze(&secret_program)
            .expect_err("nested Secret handles must not become List elements");
        assert_eq!(error.code, "E_LIST_RESOURCE_ELEMENT");
    }
    #[test]
    fn every_list_method_has_a_typed_safe_surface() {
        let program = parse(
            "fn methods() -> List<(int, int), 4> {\
                 var List<int, 4> values = [1, 2];\
                 let length = values.len();\
                 let Option<int> first = values.get(0);\
                 let changed = values.try_set(index: 0, value: 3);\
                 let pushed = values.try_push(4);\
                 let _ = changed;\
                 let _ = pushed;\
                 let has_three = values.contains(3);\
                 let Option<int> removed = values.pop();\
                 let List<int, 2> head = values.take(2);\
                 values.enumerate()\
             }",
        )
        .expect("parse List methods");
        let typed = analyze(&program).expect("analyze List methods");
        let TypedItem::Function(function) = &typed.items[0];
        assert_eq!(
            function.body.tail.as_ref().expect("enumerate tail").ty,
            Type::List(Box::new(Type::Tuple(vec![Type::Int, Type::Int])), 4)
        );
        let error =
            analyze_error("fn immutable() { let List<int, 2> values = [1]; values.try_push(2); }");
        assert_eq!(error.code, "E_LIST_MUTABLE_RECEIVER");
        let error = analyze_error("fn temporary() { let pushed = [1].try_push(2); }");
        assert_eq!(error.code, "E_LIST_MUTABLE_RECEIVER");
        // Receiver methods accept positional arguments or their declared labels.
        for source in [
            "fn positional() { var List<int, 2> values = [1]; let _ = values.try_set(0, 1); values.set(0, 2); }",
            "fn labelled() { var List<string, 2> values = [\"a\"]; let _ = values.try_set(index: 0, value: \"b\"); values.set(index: 0, value: \"c\"); }",
            "fn mixed() { var List<int, 2> values = [1]; values.set(0, value: 2); }",
        ] {
            analyze(&parse(source).expect("List method call parses"))
                .unwrap_or_else(|error| panic!("{source}: {error:?}"));
        }
    }
    #[test]
    fn list_mutators_accept_stable_fields_of_mutable_local_products() {
        let declarations = "struct Item { int value; } struct Holder { List<Item, 3> items; }";
        for body in [
            "var holder = Holder { items: [Item { value: 1 }] }; holder.items.push(Item { value: 2 }); holder.items.set(0, Item { value: 3 }); let _ = holder.items.pop();",
            "var pair = (0, Holder { items: [] }); let _ = pair.1.items.try_push(Item { value: 2 });",
        ] {
            let text = format!("module Lists {{ {declarations} fn run() {{ {body} }} }}");
            analyze(&parse(&text).unwrap()).unwrap_or_else(|error| panic!("{text}: {error:?}"));
            let source =
                crate::source::SourceFile::new(crate::source::SourceId(72), "list-fields.ko", text);
            let (spanned, _) =
                crate::parser::parse_source_spanned(&source, crate::source::FrontendBudget::v1())
                    .unwrap();
            let resolved = crate::resolved::resolve(spanned, &source).unwrap();
            SemanticContext::new()
                .analyze_resolved(&resolved)
                .expect("resolved root retains mutable binding identity");
        }
        for body in [
            "let holder = Holder { items: [] }; holder.items.push(Item { value: 1 });",
            "Holder { items: [] }.items.push(Item { value: 1 });",
            "if flag { var holder = Holder { items: [] }; } else { let holder = Holder { items: [] }; holder.items.push(Item { value: 1 }); }",
        ] {
            let text = format!("module Lists {{ {declarations} fn run(bool flag) {{ {body} }} }}");
            assert_eq!(
                analyze(&parse(&text).unwrap()).unwrap_err().code,
                "E_LIST_MUTABLE_RECEIVER",
                "{body}"
            );
        }
    }
    #[test]
    fn list_capacity_widens_only_at_user_arguments_and_returns() {
        for source in [
            "fn consume(List<int, 4> values) -> int { values.len() } fn run() -> int { let values = [1, 2]; consume(values) }",
            "fn run() -> List<int, 4> { let values = [1, 2]; values }",
            "fn run() -> List<int, 4> { let values = [1, 2]; return values; }",
            "fn run(bool flag) -> List<int, 4> { let values = [1, 2]; if flag { values } else { [] } }",
            "fn run(Option<int> flag) -> List<int, 4> { let values = [1, 2]; match flag { Option::some(_) => { values }, Option::none => { [] } } }",
            "fn consume(List<int, 4> values) -> int { values.len() } fn run(bool flag) -> int { let values = [1, 2]; consume(if flag { values } else { [] }) }",
        ] {
            analyze(&parse(source).unwrap()).unwrap_or_else(|error| panic!("{source}: {error:?}"));
        }
        for source in [
            "fn run() { let values = [1, 2]; let List<int, 4> other = values; }",
            "fn run() -> List<int, 1> { let values = [1, 2]; values }",
            "fn consume(List<int, 1> values) {} fn run() { let values = [1, 2]; consume(values); }",
            "fn consume(List<List<int, 3>, 2> values) {} fn run() { let List<List<int, 2>, 1> values = [[1]]; consume(values); }",
            "seiyaku Lists { state List<int, 4> saved; kotoage fn run() authorize(anyone) { let values = [1, 2]; saved = values; } }",
            "struct Holder { List<int, 4> values; } fn run() { let values = [1, 2]; let holder = Holder { values: values }; }",
            "fn run(bool flag) -> List<int, 4> { let values = [1, 2]; let List<int, 4> invalid = if flag { values } else { [] }; invalid }",
        ] {
            analyze(&parse(source).unwrap()).expect_err(source);
        }
    }
    #[test]
    fn definitely_full_push_is_rejected_without_guessing_mutable_aliases() {
        let error = analyze_error("fn run() { var values = [1, 2]; values.push(3); }");
        assert_eq!(error.code, "E_LIST_PROVABLY_FULL");
        for source in [
            "fn run() { var values = [1, 2]; let _ = values.try_push(3); }",
            "fn run() { var values = [1, 2]; let _ = values.pop(); values.push(3); }",
            "fn run(int next) { var values = [1, 2]; values.push(next); }",
            "fn run() { var List<int, 3> values = [1, 2]; values.push(3); }",
        ] {
            analyze(&parse(source).unwrap()).unwrap_or_else(|error| panic!("{source}: {error:?}"));
        }
    }
    #[test]
    fn sourced_mutable_list_receiver_retains_its_binding_identity() {
        let source = crate::source::SourceFile::new(
            crate::source::SourceId(41),
            "mutable-list.ko",
            "seiyaku Lists { view fn main() authorize(anyone) { var List<int, 2> values = [1]; let _ = values.try_push(2); } }",
        );
        let (spanned, _) =
            crate::parser::parse_source_spanned(&source, crate::source::FrontendBudget::v1())
                .expect("parse sourced mutable List receiver");
        analyze(&spanned.program).expect("source provenance must not hide the mutable binding");
    }
    #[test]
    fn list_mutability_does_not_leak_between_sibling_lexical_bindings() {
        for (index, body) in [
            "if flag { var List<int, 2> values = [1]; } else { let List<int, 2> values = [1]; values.try_push(2); }",
            "if flag { let List<int, 2> values = [1]; values.try_push(2); } else { var List<int, 2> values = [1]; }",
        ]
        .into_iter()
        .enumerate()
        {
            let text = format!("seiyaku Lists {{ view fn main(bool flag) authorize(anyone) {{ {body} }} }}");
            let raw = parse(&text).expect("parse raw sibling List bindings");
            let raw_error =
                analyze(&raw).expect_err("raw-AST fallback must preserve lexical mutability");
            assert_eq!(raw_error.code, "E_LIST_MUTABLE_RECEIVER", "{body}");
            let source = crate::source::SourceFile::new(
                crate::source::SourceId(42 + index as u32),
                format!("list-sibling-{index}.ko"),
                text,
            );
            let (spanned, _) =
                crate::parser::parse_source_spanned(&source, crate::source::FrontendBudget::v1())
                    .expect("parse sourced sibling List bindings");
            let resolved =
                crate::resolved::resolve(spanned, &source).expect("resolve sibling bindings");
            let resolved_error = SemanticContext::new()
                .analyze_resolved(&resolved)
                .expect_err("BindingId mutability must reject the immutable sibling");
            assert!(
                resolved_error
                    .failures
                    .iter()
                    .any(|failure| failure.error.code == "E_LIST_MUTABLE_RECEIVER"),
                "{body}: {resolved_error:?}"
            );
        }
    }
    #[test]
    fn list_take_accepts_zero_and_rejects_limits_above_source_capacity() {
        let zero = function_tail(
            "fn zero() -> List<int, 1> { let List<int, 4> values = [1, 2]; values.take(0) }",
        );
        assert_eq!(zero.ty, Type::List(Box::new(Type::Int), 1));
        for (source, code) in [
            (
                "fn above_source() { let List<int, 1> values = [1]; let head = values.take(2); }",
                "E_LIST_TAKE_LIMIT",
            ),
            (
                "fn large() { let values = [1]; let head = values.take(65); }",
                "E_LIST_TAKE_LIMIT",
            ),
            (
                "fn dynamic() { let values = [1]; let limit = 1; let head = values.take(limit); }",
                "E_LIST_TAKE_CONST",
            ),
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, code, "{}", error.message);
        }
    }
    #[test]
    fn list_contains_accepts_recursive_durable_aggregates() {
        let expression = function_tail(include_str!(
            "semantic/test_sources/list_contains_accepts_recursive_durable_aggregates_1.ko"
        ));
        assert_eq!(expression.ty, Type::Bool);
        assert!(
            matches!(expression.expr, ExprKind::Call { target: ref name, .. } if name.intrinsic() == Some(CompilerIntrinsic::ListContains))
        );
    }
    #[test]
    fn unchecked_list_reads_and_writes_have_actionable_diagnostics() {
        let error = analyze_error("fn read() { let values = [1]; let value = values[0]; }");
        assert_eq!(error.code, "E_LIST_UNSAFE_INDEX");
        assert!(
            error.message.contains("values.get(index)")
                || error.message.contains("list.get(index)")
        );
        let error = analyze_error("fn write() { var values = [1]; values[0] = 2; }");
        assert_eq!(error.code, "E_LIST_UNSAFE_INDEX");
        assert!(error.message.contains("set(index:"));
    }
    #[test]
    fn decimal_literals_are_exact_canonical_and_preserve_source_spelling() {
        for (spelling, canonical) in [
            ("0.0", "0"),
            ("1.250_0", "1.25"),
            ("1e3", "1000"),
            ("1.5e-3", "0.0015"),
            ("12.00e+2", "1200"),
        ] {
            let expression =
                returned_expr(&format!("fn value() -> decimal {{ return {spelling}; }}"));
            let ExprKind::DecimalLiteral {
                value,
                spelling: retained,
            } = expression.expr
            else {
                panic!("expected exact decimal literal for {spelling}");
            };
            assert_eq!(retained, spelling);
            assert_eq!(value.to_string(), canonical);
        }
    }
    #[test]
    fn decimal_literal_normalizes_before_enforcing_scale_twenty_eight() {
        let removable = format!("0.{}10", "0".repeat(27));
        let expression = returned_expr(&format!("fn value() -> decimal {{ return {removable}; }}"));
        let ExprKind::DecimalLiteral { value, .. } = expression.expr else {
            panic!("expected normalized decimal literal");
        };
        assert_eq!(value.mantissa().to_string(), "1");
        assert_eq!(value.scale(), 28);
        let zero = format!("0.{}", "0".repeat(80));
        let expression = returned_expr(&format!("fn value() -> decimal {{ return {zero}; }}"));
        let ExprKind::DecimalLiteral { value, .. } = expression.expr else {
            panic!("expected canonical zero");
        };
        assert!(value.is_zero());
        assert_eq!(value.scale(), 0);
        let nonremovable = format!("0.{}1", "0".repeat(28));
        let error = analyze_error(&format!(
            "fn value() -> decimal {{ return {nonremovable}; }}"
        ));
        assert_eq!(error.code, "E_DECIMAL_SCALE_OVERFLOW");
    }
    #[test]
    fn int_literal_accepts_both_signed_512_bit_endpoints_and_rejects_neighbors() {
        fn decimal_plus_one(value: &str) -> String {
            let mut digits = value.as_bytes().to_vec();
            let mut carry = true;
            for digit in digits.iter_mut().rev() {
                if !carry {
                    break;
                }
                if *digit == b'9' {
                    *digit = b'0';
                } else {
                    *digit += 1;
                    carry = false;
                }
            }
            if carry {
                digits.insert(0, b'1');
            }
            String::from_utf8(digits).expect("decimal digits")
        }
        let mut maximum_bytes = vec![0xff; 64];
        maximum_bytes[63] = 0x7f;
        let maximum = BigInt::from_twos_bytes(&maximum_bytes).expect("signed 512-bit maximum");
        let mut minimum_bytes = vec![0; 64];
        minimum_bytes[63] = 0x80;
        let minimum = BigInt::from_twos_bytes(&minimum_bytes).expect("signed 512-bit minimum");
        let maximum_expression =
            returned_expr(&format!("fn value() -> int {{ return {maximum}; }}"));
        assert!(matches!(maximum_expression.expr, ExprKind::IntLiteral(value) if value == maximum));
        let minimum_expression =
            returned_expr(&format!("fn value() -> int {{ return {minimum}; }}"));
        assert!(matches!(minimum_expression.expr, ExprKind::IntLiteral(value) if value == minimum));
        let above = decimal_plus_one(&maximum.to_string());
        let below_magnitude = decimal_plus_one(minimum.to_string().trim_start_matches('-'));
        for source in [
            format!("fn value() -> int {{ return {above}; }}"),
            format!("fn value() -> int {{ return -{below_magnitude}; }}"),
        ] {
            let error = parse(&source).expect_err("neighbor outside signed 512-bit range");
            assert!(error.contains("E_INT_LITERAL_OVERFLOW"), "{error}");
        }
    }
    #[test]
    fn decimal_literal_accepts_signed_minimum_after_combining_unary_minus() {
        let mut minimum_bytes = vec![0; MAX_MANTISSA_BYTES];
        minimum_bytes[MAX_MANTISSA_BYTES - 1] = 0x80;
        let minimum = BigInt::from_twos_bytes(&minimum_bytes).expect("signed 512-bit minimum");
        let magnitude = minimum.to_string().trim_start_matches('-').to_owned();
        let expression = returned_expr(&format!(
            "fn value() -> decimal {{ return -{magnitude}.0; }}"
        ));
        assert!(matches!(
            expression.expr,
            ExprKind::DecimalLiteral { ref value, .. }
                if value.mantissa() == &minimum && value.scale() == 0
        ));
        let error = analyze_error(&format!(
            "fn value() -> decimal {{ return {magnitude}.0; }}"
        ));
        assert_eq!(error.code, "E_DECIMAL_MANTISSA_OVERFLOW");
    }
    #[test]
    fn decimal_literal_ignores_leading_zeroes_before_width_checks() {
        let expression = returned_expr(&format!(
            "fn value() -> decimal {{ return {}1e1; }}",
            "0".repeat(1_000)
        ));
        assert!(matches!(
            expression.expr,
            ExprKind::DecimalLiteral { ref value, .. } if value.to_string() == "10"
        ));
    }
    #[test]
    fn exact_constant_numeric_arithmetic_uses_runtime_primitives() {
        for (source, expected) in [
            ("1.20 + 2.3", "3.5"),
            ("5.0 - 1.25", "3.75"),
            ("1.5 * 2.0", "3"),
            ("1.0 / 8.0", "0.125"),
        ] {
            let expression =
                returned_expr(&format!("fn value() -> decimal {{ return {source}; }}"));
            let ExprKind::DecimalLiteral { value, .. } = expression.expr else {
                panic!("constant decimal expression {source} must fold");
            };
            assert_eq!(value.to_string(), expected);
        }
        for (source, expected_code) in [
            (
                "fn value() -> quantity { return 1 - 2; }",
                "E_QUANTITY_UNDERFLOW",
            ),
            (
                "fn value() -> decimal { return 1.0 / 0.0; }",
                "E_DIVISION_BY_ZERO",
            ),
            (
                "fn value() -> decimal { return 1.0 / 3.0; }",
                "E_REPEATING_DECIMAL",
            ),
            (
                "fn value() -> decimal { return 0.000000000000001 * 0.000000000000001; }",
                "E_DECIMAL_SCALE_OVERFLOW",
            ),
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, expected_code, "{}", error.message);
        }
    }
    #[test]
    fn exact_literals_inherit_decimal_and_quantity_expression_context() {
        let program = parse(
            "const decimal EIGHTH = 1 / 8; \
             fn value(quantity balance) -> (bool, quantity, quantity) { \
                 return (balance == 0, balance + 1, balance * 2); \
             } \
             fn tuple_literals() -> (decimal, quantity) { \
                 return (1 / 8, 2); \
             }",
        )
        .expect("parse contextual numeric literals");
        analyze(&program).expect("exact literals must inherit their numeric expression context");
        let repeating = analyze_error("const decimal THIRD = 1 / 3;");
        assert_eq!(repeating.code, "E_REPEATING_DECIMAL");
        let underflow = analyze_error("const quantity INVALID = 1 - 2;");
        assert_eq!(underflow.code, "E_QUANTITY_UNDERFLOW");
        let negative = analyze_error("const quantity INVALID = -1;");
        assert_eq!(negative.code, "E_NEGATIVE_QUANTITY");
        let scaled =
            returned_expr("fn scaled(quantity balance) -> quantity { return balance / 2; }");
        assert_eq!(scaled.ty, Type::Quantity);
        let ratio = returned_expr("fn ratio(quantity balance) -> decimal { return balance / 2; }");
        assert_eq!(ratio.ty, Type::Decimal);
    }
    #[test]
    fn ternary_literals_inherit_the_enclosing_numeric_context() {
        let program = parse(
            "fn decimal_choice(bool flag, decimal value) -> decimal { \
                 return flag ? value : 1; \
             } \
             fn quantity_choice(bool flag, quantity value) -> quantity { \
                 return flag ? 1 : value; \
             } \
             fn literal_choice(bool flag) -> decimal { \
                 return flag ? 1 : 2; \
             }",
        )
        .expect("parse contextual ternary literals");
        let typed = analyze(&program).expect("ternary literals must inherit their return context");
        for item in typed.items {
            let TypedItem::Function(function) = item;
            let return_type = function.ret_ty.clone().expect("return type");
            let TypedStatement::Return(Some(value)) = &function.body.statements[0] else {
                panic!("expected a returned ternary")
            };
            let ExprKind::Conditional {
                then_expr,
                else_expr,
                ..
            } = value.kind()
            else {
                panic!("expected a typed ternary")
            };
            assert_eq!(then_expr.ty, return_type);
            assert_eq!(else_expr.ty, return_type);
        }
    }
    #[test]
    fn raw_semantic_analysis_does_not_leak_range_iterators() {
        let program = parse("fn invalid() -> int { for index in range(1) {} return index; }")
            .expect("parse range iterator scope");
        let error = analyze(&program).expect_err("the iterator must end with the loop scope");
        assert_eq!(error.code, "K2002");
        assert!(error.message.contains("undefined variable index"));
    }
    include!("semantic/tests/numeric_rounding_modes.rs");
    #[test]
    fn unknown_rounding_spellings_are_rejected() {
        for mode in ["nearest", "bankers", "nearest_toward"] {
            let error = analyze_error(&format!(
                "fn value() -> decimal {{ 1.0.div_round(\
                    divisor: 8.0, scale: 2, mode: Rounding::{mode}) }}"
            ));
            assert_eq!(error.code, "E_NUMERIC_ROUNDING_MODE", "mode={mode}");
            assert_eq!(
                error.message,
                format!(
                    "decimal.div_round mode must be one of {}",
                    V1_ROUNDING_PATHS.join(", ")
                ),
                "mode={mode}",
            );
        }
    }
    #[test]
    fn rounded_numeric_methods_reject_noncanonical_signatures() {
        // Rounded methods are receiver methods: positional and labelled
        // arguments are the same call.
        analyze(
            &parse(
                "fn value(decimal input) -> decimal { \
                    input.div_round(2.0, 2, Rounding::nearest_even) }",
            )
            .expect("positional rounded call parses"),
        )
        .expect("rounded receiver methods accept positional arguments");

        let int_receiver = analyze_error(
            "fn value(int input) -> decimal { \
                input.div_round( \
                    divisor: 2.0, scale: 2, mode: Rounding::nearest_even) }",
        );
        assert_eq!(int_receiver.code, "E_NUMERIC_ROUND_RECEIVER");
        let decimal_ratio = analyze_error(
            "fn value(decimal input, quantity divisor) -> decimal { \
                input.ratio_round( \
                    divisor: divisor, scale: 2, mode: Rounding::nearest_even) }",
        );
        assert_eq!(decimal_ratio.code, "E_NUMERIC_ROUND_RECEIVER");
        for scale in ["-1", "29"] {
            let error = analyze_error(&format!(
                "fn value(decimal input) -> decimal {{ \
                    input.div_round( \
                        divisor: 2.0, scale: {scale}, mode: Rounding::nearest_even) }}"
            ));
            assert_eq!(error.code, "E_INVALID_SCALE", "scale={scale}");
        }
    }
    #[test]
    fn explicit_numeric_conversions_preserve_failure_and_rounding_policy() {
        let recoverable = returned_expr(
            "fn convert(decimal value) -> Result<quantity, NumericError> { \
                return quantity::try_from_decimal(value); }",
        );
        assert_eq!(
            recoverable.ty,
            Type::Result(
                Box::new(Type::Quantity),
                Box::new(Type::ErrorEnum(Arc::new(
                    ivm_abi::error_types::numeric_error_type()
                )))
            )
        );
        assert!(matches!(recoverable.expr, ExprKind::NumericTryCast { .. }));
        let truncated = returned_expr("fn value() -> int { return decimal::to_int_trunc(-1.9); }");
        assert!(
            matches!(truncated.expr, ExprKind::IntLiteral(ref value) if value.try_to_i64() == Some(-1))
        );
        let rounded = returned_expr(
            "fn value() -> int { return decimal::to_int_round(\
                2.5, mode: Rounding::nearest_even); }",
        );
        assert!(
            matches!(rounded.expr, ExprKind::IntLiteral(ref value) if value.try_to_i64() == Some(2))
        );
    }
    #[test]
    fn named_struct_fields_retain_source_evaluation_order() {
        let expr = returned_expr(
            "struct Transfer { int source, string destination, quantity amount } fn build() -> Transfer { return Transfer { amount: 10, destination: \"sink\", source: 7 }; }",
        );
        assert!(
            matches!(expr.ty, Type::Struct { ref name, .. } if name == "TestContract::Transfer")
        );
        let ExprKind::StructLiteral { name, fields } = expr.expr else {
            panic!("expected typed struct literal");
        };
        assert_eq!(name, "TestContract::Transfer");
        assert_eq!(
            fields
                .iter()
                .map(|(field, _)| field.as_str())
                .collect::<Vec<_>>(),
            ["amount", "destination", "source"]
        );
        assert!(matches!(fields[0].1.expr, ExprKind::DecimalLiteral { .. }));
        assert!(matches!(fields[1].1.expr, ExprKind::String(ref value) if value == "sink"));
        assert!(
            matches!(fields[2].1.expr, ExprKind::IntLiteral(ref value) if value == &BigInt::from(7_i64))
        );
    }
    #[test]
    fn struct_literals_reject_unknown_missing_and_positional_fields() {
        for (source, code) in [
            (
                "struct Pair { int first, string second } fn build() -> Pair { return Pair { first: 1, second: \"two\", third: 3 }; }",
                "E_UNKNOWN_STRUCT_FIELD",
            ),
            (
                "struct Pair { int first, string second } fn build() -> Pair { return Pair { first: 1 }; }",
                "E_MISSING_STRUCT_FIELD",
            ),
            (
                "struct Pair { int first, string second } fn build() -> Pair { return Pair(1, \"two\"); }",
                "E_POSITIONAL_STRUCT",
            ),
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, code, "{}", error.message);
        }
    }
    #[test]
    fn named_user_call_arguments_are_reordered_to_parameter_order() {
        let program = parse(
            "fn target(int first, string second) -> int { return first; } fn main() -> int { return target(second: \"two\", first: 1); }",
        )
        .expect("parse named user call");
        let typed = analyze(&program).expect("analyze named user call");
        let main = typed
            .items
            .into_iter()
            .find_map(|item| {
                let TypedItem::Function(function) = item;
                (function.name == "main").then_some(function)
            })
            .expect("main function");
        let TypedStatement::Return(Some(call)) = &main.body.statements[0] else {
            panic!("expected returned call");
        };
        let ExprKind::NamedCall {
            args,
            evaluation_order,
            ..
        } = &call.expr
        else {
            panic!("expected typed call");
        };
        assert!(matches!(args[0].expr, ExprKind::IntLiteral(ref value) if value == &BigInt::one()));
        assert!(matches!(args[1].expr, ExprKind::String(ref value) if value == "two"));
        assert_eq!(evaluation_order, &[1, 0]);
    }
    #[test]
    fn named_user_calls_reject_unknown_and_missing_arguments() {
        for (source, code) in [
            (
                "fn target(int first, string second) {} fn main() { target(first: 1, third: \"three\"); }",
                "E_UNKNOWN_NAMED_ARGUMENT",
            ),
            (
                "fn target(int first, string second) {} fn main() { target(first: 1); }",
                "E_MISSING_NAMED_ARGUMENT",
            ),
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, code, "{}", error.message);
        }
        let named =
            parse("fn target(int left, int right) {} fn main() { target(right: 2, left: 1); }")
                .expect("parse repeated-type named call");
        analyze(&named).expect("named repeated-type call should type-check");
    }
    #[test]
    fn named_argument_plans_reject_optional_holes_without_compacting_abi_slots() {
        let parameters = vec![
            "required".to_owned(),
            "first_optional".to_owned(),
            "second_optional".to_owned(),
        ];
        let required = [true, false, false];
        let args = vec![
            Expr::IntLiteral(BigInt::one()),
            Expr::IntLiteral(BigInt::from(3_u32)),
        ];
        let names = vec![
            Some("required".to_owned()),
            Some("second_optional".to_owned()),
        ];
        let error = reorder_call_arguments(
            "internal_optional_fixture",
            &args,
            Some(&names),
            false,
            &parameters,
            &required,
            0,
        )
        .expect_err("a later optional argument cannot occupy an earlier omitted ABI slot");
        assert_eq!(error.code, "E_NAMED_ARGUMENT_HOLE");
        assert!(error.message.contains("first_optional"));
        assert!(error.message.contains("second_optional"));
        let trailing_names = vec![Some("required".to_owned())];
        let trailing = reorder_call_arguments(
            "internal_optional_fixture",
            &args[..1],
            Some(&trailing_names),
            false,
            &parameters,
            &required,
            0,
        )
        .expect("omitting only a trailing optional suffix remains canonical");
        assert_eq!(trailing.ordered.len(), 1);
        assert_eq!(trailing.evaluation_order, [0]);
        let interior_optional_parameters = vec![
            "required".to_owned(),
            "optional_payload".to_owned(),
            "required_trailer".to_owned(),
        ];
        let interior_required = [true, false, true];
        let interior_args = vec![
            Expr::IntLiteral(BigInt::one()),
            Expr::IntLiteral(BigInt::from(2_u32)),
        ];
        let interior_names = vec![
            Some("required".to_owned()),
            Some("required_trailer".to_owned()),
        ];
        let interior = reorder_call_arguments(
            "compacted_optional_fixture",
            &interior_args,
            Some(&interior_names),
            false,
            &interior_optional_parameters,
            &interior_required,
            0,
        )
        .expect("a required trailer unambiguously follows an omitted optional payload");
        assert_eq!(interior.ordered.len(), 2);
        assert_eq!(interior.evaluation_order, [0, 1]);
    }
    analyze_error_code_cases! {
        declared_call_labels_are_independent_of_effects:
        privileged = "permission Publish; kotoage fn publish(int first, string second, bool third) authorize(Publish) {} fn main() { publish(1, \"two\", true); }" => "K2004";
        effectful = "fn main(AccountId holder, Name key, Json value) { ledger::account::set_metadata(holder, key, value); }" => "E_NAMED_ARGUMENTS_REQUIRED";
        transitive = "fn sink(AccountId account, Name key, Json value) { ledger::account::set_metadata(account: account, key: key, value: value); } fn wrapper(AccountId account, Name key, Json value) { sink(account: account, key: key, value: value); } fn main(AccountId account, Name key, Json value) { wrapper(account, key); }" => "E_MISSING_NAMED_ARGUMENT";
    }
    analyze_ok_tests! { named_method_arguments_do_not_mix_with_the_receiver: "state StateMap<int, int> values; fn lookup(int key) -> int { return values.get_or_insert(default: 0, key: key); }" => "parse named method call", "implicit receiver must not count as a positional argument"; }
    #[test]
    fn sum_error_bridges_preserve_nominal_types_and_private_helper_names() {
        let source = r#"module Bridges {
            error enum Previous { Denied = 1 }
            error enum Failure { Missing = 7 }
            fn convert(Option<int> value) -> Result<int, Failure> {
                Result::ok(value.ok_or(error: Failure::Missing)?)
            }
            fn absent() -> Result<int, Failure> { Option::none.ok_or(Failure::Missing) }
            fn replace(Result<int, Previous> value) -> Result<int, Failure> {
                value.or_err(error: Failure::Missing)
            }
            fn extract(Result<(int, bool), Previous> value) -> (int, bool) {
                value.expect(error: Failure::Missing)
            }
            fn ok_or(int value) -> int { value }
            fn or_err(int value) -> int { value }
            fn helpers() -> int { ok_or(1) + or_err(2) }
        }"#;
        let typed = analyze(&parse(source).expect("parse nominal error bridges"))
            .expect("bridges preserve payload types and private method-name helpers");
        crate::ir::lower(&typed).expect("bridges lower with compiler-owned call identities");
        for body in [
            "fn bad(Option<int> value) -> Result<int, Failure> { value.ok_or(1) }",
            "fn bad(Result<int, Previous> value) -> Result<int, Failure> { value.or_err(\"no\") }",
            "fn bad(Option<int> value) -> Result<int, Failure> { value.or_err(Failure::Missing) }",
            "fn bad(Result<int, Previous> value) -> Result<int, Failure> { value.ok_or(Failure::Missing) }",
            "fn bad(int value) -> int { value.expect(Failure::Missing) }",
        ] {
            let source = format!(
                "module Invalid {{ error enum Previous {{ Denied = 1 }} error enum Failure {{ Missing = 7 }} {body} }}"
            );
            assert_eq!(analyze_error(&source).code, "K2003", "{source}");
        }
        let mismatched = "module Invalid { error enum Previous { Denied = 1 } error enum Failure { Missing = 7 } fn convert(Option<int> value) -> Result<int, Previous> { Result::ok(value.ok_or(Failure::Missing)?) } }";
        assert_eq!(analyze_error(mismatched).code, "E_PROPAGATE_ERROR_TYPE");
    }
    #[test]
    fn public_parameters_reject_keyword_fields_before_abi_lowering() {
        let source = "seiyaku Boundary { view fn read(Name permission) authorize(anyone) -> Name { permission } }";
        let diagnostics = crate::session::CompilerSession::default()
            .check(crate::session::CompileRequest {
                source,
                source_name: Some("boundary.ko"),
            })
            .expect_err("keyword parameter has no canonical ABI field");
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(
            diagnostic.code,
            "E_PUBLIC_PARAMETER_IDENTIFIER",
            "{}",
            diagnostics.render_human()
        );
        let range = diagnostic
            .primary_span
            .as_ref()
            .and_then(|span| span.byte_range)
            .expect("exact public parameter token");
        assert_eq!(
            &source[range.start as usize..range.end as usize],
            "permission"
        );
        analyze(
            &parse("fn private_parameter(Name permission) -> Name { permission }")
                .expect("contextual private parameter parses"),
        )
        .expect("private parameters do not cross the public ABI identifier boundary");
        analyze(
            &parse(
                "seiyaku Boundary { view fn read(int anyone) authorize(anyone) -> int { anyone } }",
            )
            .unwrap(),
        )
        .expect("anyone is contextual to authorization, not a general keyword");
    }
    #[test]
    fn permission_grants_require_a_declared_instance_name() {
        let source = |argument: &str| {
            format!(
                r#"seiyaku Grants {{
            permission Admin; permission Pay; import permission "CanSetParameters" as ChainAdmin;
            kotoage fn grant(AccountId account) authorize(Admin) {{ ledger::seiyaku::grant_permission(account: account, permission: {argument}); }}
        }}"#
            )
        };
        analyze(&parse(&source("Pay")).expect("parse instance grant"))
            .expect("declared instance grant");
        for argument in ["\"Pay\"", "Name::parse(\"Pay\")", "ChainAdmin"] {
            let error = analyze(&parse(&source(argument)).expect("parse invalid grant"))
                .expect_err("grants require instance declaration identifiers");
            assert_eq!(error.code, "E_PERMISSION_ARGUMENT", "{}", error.message);
        }
        let module = analyze_error(
            r#"module Helpers { export fn allow(AccountId account) { ledger::seiyaku::grant_permission(account: account, permission: "Pay"); } }"#,
        );
        assert_eq!(module.code, "E_PERMISSION_ARGUMENT");
    }
    #[test]
    fn asset_registration_takes_compile_time_spec_and_mintability() {
        let source = |spec: &str, mintable: &str| {
            format!(
                "fn reg(AssetDefinitionId asset) {{ ledger::asset::register(asset_definition: asset, \
                 name: \"Rose\", spec: {spec}, mintable: {mintable}); }}"
            )
        };
        let typed = analyze(
            &parse(&source(
                "NumericSpec::fractional(2)",
                "Mintable::Limited(3)",
            ))
            .expect("parse register"),
        )
        .expect("nominal constructors fold");
        let TypedItem::Function(function) = &typed.items[0];
        let TypedStatement::Expr(call) = &function.body.statements[0] else {
            panic!("register statement");
        };
        let (ExprKind::Call { args, .. } | ExprKind::NamedCall { args, .. }) = call.kind() else {
            panic!("register call");
        };
        assert!(
            matches!(args[2].kind(), ExprKind::IntLiteral(word) if word.try_to_u64() == Some(3))
        );
        assert!(
            matches!(args[3].kind(), ExprKind::IntLiteral(word) if word.try_to_u64() == Some((3 << 2) | 3))
        );
        for (spec, mintable, fragment) in [
            (
                "2",
                "Mintable::Once",
                "`spec:` of `ledger::asset::register` takes",
            ),
            (
                "NumericSpec::integer()",
                "1",
                "`mintable:` of `ledger::asset::register` takes",
            ),
            (
                "NumericSpec::integer()",
                "Mintable::once",
                "did you mean `Mintable::Once`?",
            ),
            (
                "NumericSpec::integer()",
                "Mintable::Once()",
                "write `Mintable::Once` without parentheses",
            ),
            (
                "NumericSpec::integer",
                "Mintable::Once",
                "write `NumericSpec::integer(...)`",
            ),
            (
                "NumericSpec::fractional(29)",
                "Mintable::Once",
                "must be in 0..=28",
            ),
            (
                "NumericSpec::integer()",
                "Mintable::Limited(0)",
                "must be in 1..=",
            ),
        ] {
            let error = analyze(&parse(&source(spec, mintable)).expect("parse register"))
                .expect_err("invalid nominal argument");
            assert_eq!(error.code, "E_NOMINAL_ARGUMENT", "{}", error.message);
            assert!(error.message.contains(fragment), "{}", error.message);
        }
        for misplaced in [
            "fn f() { let _ = Mintable::Limited(2); }",
            "fn f() { let _ = NumericSpec::integer(); }",
        ] {
            let error = analyze_error(misplaced);
            assert_eq!(error.code, "E_NOMINAL_ARGUMENT", "{}", error.message);
            assert!(
                error.message.contains("write it directly as the `"),
                "{}",
                error.message
            );
        }
        let error = analyze_error(
            "fn reg(AssetDefinitionId asset) { ledger::asset::register(asset_definition: asset, name: \"a#b\", spec: NumericSpec::integer(), mintable: Mintable::Not); }",
        );
        assert_eq!(error.code, "E_ASSET_NAME_INVALID");
        assert_eq!(
            error.message,
            "invalid `name:` display name for ledger::asset::register: asset name must not contain `#` or `@`"
        );
    }
    #[test]
    fn signature_scheme_arguments_fold_to_host_codes() {
        let source = |scheme: &str| {
            format!(
                "fn check(bytes payload) -> bool {{ return crypto::verify_signature(message: payload, \
                 signature: payload, public_key: payload, scheme: {scheme}); }}"
            )
        };
        for (scheme, code) in [
            ("SignatureScheme::Ed25519", 1_u64),
            ("SignatureScheme::Secp256k1", 2),
            ("SignatureScheme::MlDsa", 3),
        ] {
            let typed = analyze(&parse(&source(scheme)).expect("parse verify"))
                .expect("scheme value folds");
            let TypedItem::Function(function) = &typed.items[0];
            let TypedStatement::Return(Some(call)) = &function.body.statements[0] else {
                panic!("return statement");
            };
            let (ExprKind::Call { args, .. } | ExprKind::NamedCall { args, .. }) = call.kind()
            else {
                panic!("verify call");
            };
            assert!(
                matches!(args[3].kind(), ExprKind::IntLiteral(word) if word.try_to_u64() == Some(code)),
                "{scheme}"
            );
        }
        for (scheme, fragment) in [
            (
                "1",
                "`scheme:` of `crypto::verify_signature` takes a `SignatureScheme` value",
            ),
            (
                "SignatureScheme::Sm2",
                "`SignatureScheme::Ed25519`, `SignatureScheme::Secp256k1`, `SignatureScheme::MlDsa`",
            ),
            (
                "SignatureScheme::ed25519",
                "did you mean `SignatureScheme::Ed25519`?",
            ),
            ("Mintable::Once", "takes a `SignatureScheme` value"),
        ] {
            let error = analyze(&parse(&source(scheme)).expect("parse verify"))
                .expect_err("invalid scheme");
            assert_eq!(error.code, "E_NOMINAL_ARGUMENT", "{}", error.message);
            assert!(error.message.contains(fragment), "{}", error.message);
        }
    }
    /// Check `source` and return the first semantic diagnostic's message, help
    /// and primary-span text.
    fn first_checked_diagnostic(source: &str) -> (String, Option<String>, Option<String>) {
        let diagnostics = crate::session::CompilerSession::default()
            .check(crate::session::CompileRequest {
                source,
                source_name: Some("probe.ko"),
            })
            .expect_err("source must be rejected");
        let diagnostic = diagnostics
            .diagnostics
            .first()
            .expect("one diagnostic")
            .clone();
        let primary = diagnostic
            .primary_span
            .and_then(|span| span.byte_range)
            .map(|range| source[range.start as usize..range.end as usize].to_owned());
        (diagnostic.message, diagnostic.help, primary)
    }
    #[test]
    fn nominal_argument_errors_point_at_the_argument_with_type_specific_help() {
        for (argument, descriptor, call) in [
            (
                "2",
                "NumericSpec",
                "ledger::asset::register(asset_definition: asset, name: \"Rose\", spec: 2, mintable: Mintable::Once)",
            ),
            (
                "mode",
                "Mintable",
                "ledger::asset::register(asset_definition: asset, name: \"Rose\", spec: NumericSpec::integer(), mintable: mode)",
            ),
            (
                "1",
                "SignatureScheme",
                "let _ok = crypto::verify_signature(message: b\"m\", signature: b\"s\", public_key: b\"k\", scheme: 1)",
            ),
        ] {
            let source = format!(
                "seiyaku Probe {{ permission ProbeAccess;  kotoage fn probe(AssetDefinitionId asset, int mode) authorize(ProbeAccess) {{ {call}; }} }}"
            );
            let (message, help, primary) = first_checked_diagnostic(&source);
            assert!(message.contains(descriptor), "{message}");
            assert_eq!(primary.as_deref(), Some(argument), "{message}");
            let help = help.expect("site-specific help");
            assert_eq!(help, nominal_argument_help(descriptor));
            for other in ["NumericSpec", "Mintable", "SignatureScheme"] {
                assert_eq!(
                    help.contains(&format!("`{other}::")),
                    other == descriptor,
                    "{help}"
                );
            }
        }
    }
    #[test]
    fn invalid_json_key_literals_point_at_the_key_with_name_help() {
        let source = "seiyaku Probe { view fn v() authorize(anyone) -> int { return read(json { a: \"1\" }); } fn read(Json value) -> int { return value.get_int(\"a b\").unwrap_or(0); } }";
        let (message, help, primary) = first_checked_diagnostic(source);
        assert!(
            message.starts_with("JSON key invalid Name literal"),
            "{message}"
        );
        assert_eq!(primary.as_deref(), Some("\"a b\""));
        let help = help.expect("JSON key help");
        assert!(
            help.starts_with("A typed JSON getter key is a `Name`."),
            "{help}"
        );
        assert!(!help.contains("account"), "{help}");
    }
    #[test]
    fn invalid_asset_display_name_literals_point_at_the_name() {
        let source = "seiyaku Probe { permission ProbeAccess;  kotoage fn r(AssetDefinitionId asset) authorize(ProbeAccess) { ledger::asset::register(asset_definition: asset, name: \"ro@se\", spec: NumericSpec::integer(), mintable: Mintable::Once); } }";
        let (message, help, primary) = first_checked_diagnostic(source);
        assert_eq!(
            message,
            "invalid `name:` display name for ledger::asset::register: asset name must not contain `#` or `@`"
        );
        assert_eq!(primary.as_deref(), Some("\"ro@se\""));
        assert!(help.expect("display name help").contains("non-blank"));
    }
    #[test]
    fn unknown_labels_on_receiver_intrinsics_name_the_declared_parameters() {
        let error = analyze_error(
            "fn f(quantity amount, decimal divisor) -> quantity { \
             return amount.div_round(divisor, 2, rounding: Rounding::floor); }",
        );
        assert_eq!(error.code, "E_UNKNOWN_NAMED_ARGUMENT");
        assert!(
            error
                .message
                .ends_with("; its parameters are `divisor`, `scale`, `mode`"),
            "{}",
            error.message
        );
        // Declared labels and positional arguments both keep working.
        analyze(
            &parse(
                "fn f(quantity amount, decimal divisor) -> quantity { \
                 return amount.div_round(divisor: divisor, scale: 2, mode: Rounding::floor); }",
            )
            .expect("parse"),
        )
        .expect("declared labels are accepted");
    }
    #[test]
    fn runtime_functions_reusing_lowering_names_keep_the_runtime_call_rule() {
        for (declaration, call) in [
            (
                "view fn min(int a, int b) authorize(anyone) -> int { return a; }",
                "view fn probe() authorize(anyone) -> int { return min(1, 2); }",
            ),
            (
                "view fn block_height() authorize(anyone) -> int { return 4; }",
                "view fn probe() authorize(anyone) -> int { return block_height(); }",
            ),
            (
                "permission Mint; kotoage fn mint_asset() authorize(Mint) { }",
                "kotoage fn probe() authorize(Mint) { mint_asset(); }",
            ),
        ] {
            let error = analyze_error(&format!("seiyaku Probe {{ {declaration} {call} }}"));
            assert_eq!(error.code, "K2004", "{}", error.message);
            assert!(
                error.message.starts_with("seiyaku runtime function `"),
                "{}",
                error.message
            );
        }
        // The canonical builtin keeps working next to a view of the same
        // lowering name.
        analyze(
            &parse(
                "seiyaku Probe { view fn min(int a, int b) authorize(anyone) -> int { return a; } view fn probe() authorize(anyone) -> int { return math::min(1, 2); } }",
            )
            .expect("parse"),
        )
        .expect("math::min resolves to the builtin");
    }
    #[test]
    fn unknown_state_map_methods_teach_the_documented_surface() {
        for (method, fragment) in [
            ("get_or", "map.get(key).unwrap_or(default)"),
            ("get_or_default", "map.get(key).expect(Error::Missing)"),
            ("ensure", "map.get_or_insert(key, default)"),
            ("contans", "did you mean `contains`?"),
            ("keys", "`StateMap` methods are `get`, `contains`"),
        ] {
            let source = format!(
                "seiyaku Probe {{ state StateMap<int, int> M; view fn probe() authorize(anyone) -> int {{ let _x = M.{method}(1, 0); return 0; }} }}"
            );
            let (message, help, primary) = first_checked_diagnostic(&source);
            assert_eq!(message, format!("`StateMap` has no method `{method}`"));
            let help = help.expect("StateMap method help");
            assert!(help.contains(fragment), "{method}: {help}");
            assert_eq!(primary, Some(format!("M.{method}(1, 0)")));
        }
        assert!(!unknown_state_map_method_help("get_or").contains("did you mean"));
        // A non-StateMap receiver keeps the generic unknown-function message.
        let error = analyze_error("fn f(int x) -> int { return x.get_or(1, 0); }");
        assert!(
            error
                .message
                .contains("unknown function or builtin `get_or`"),
            "{}",
            error.message
        );
    }
    #[test]
    fn json_string_and_bool_getters_return_typed_options() {
        for (method, payload) in [("get_string", Type::String), ("get_bool", Type::Bool)] {
            let source = format!(
                "fn read(Json value) -> bool {{ return value.{method}(\"k\").is_some(); }}"
            );
            analyze(&parse(&source).expect("parse getter")).expect("getter type-checks");
            let typed = analyze(
                &parse(&format!(
                    "fn read(Json value) {{ let field = value.{method}(\"k\"); }}"
                ))
                .expect("parse getter binding"),
            )
            .expect("getter binding type-checks");
            let TypedItem::Function(function) = &typed.items[0];
            let TypedStatement::Let { value, .. } = &function.body.statements[0] else {
                panic!("let statement");
            };
            assert_eq!(value.ty, Type::Option(Box::new(payload)), "{method}");
        }
    }
    #[test]
    fn json_getters_accept_string_literal_keys_as_names() {
        let typed = analyze(
            &parse("fn read(Json value) -> Option<int> { return value.get_int(\"count\"); }")
                .expect("parse getter"),
        )
        .expect("literal keys are compile-time names");
        let TypedItem::Function(function) = &typed.items[0];
        let TypedStatement::Return(Some(call)) = &function.body.statements[0] else {
            panic!("return statement");
        };
        let ExprKind::Call { args, .. } = call.kind() else {
            panic!("getter call");
        };
        assert_eq!(args[1].ty, Type::Name);
        let error = analyze_error(
            "fn read(Json value) -> Option<int> { return value.get_int(\"two words\"); }",
        );
        assert_eq!(error.code, "E_INVALID_ID_LITERAL");
    }
    #[test]
    fn rejected_builtin_labels_render_the_labelled_call_fix() {
        let parsed = parse("fn f(NftId token, AccountId who) { ledger::nft::mint(token, who); }")
            .expect("parse call");
        let Item::Function(function) = &parsed.items[0] else {
            panic!("function");
        };
        let Statement::Expr(call) = function.body.statements[0].kind() else {
            panic!("call statement");
        };
        let Expr::Call {
            args,
            argument_names,
            ..
        } = call.kind()
        else {
            panic!("call");
        };
        assert_eq!(
            labelled_builtin_call_fix(
                "ledger::nft::mint",
                args,
                argument_names.as_deref(),
                &["nft".to_owned(), "owner".to_owned()],
            )
            .as_deref(),
            Some("ledger::nft::mint(nft: token, owner: who)")
        );
        assert_eq!(
            render_simple_expr(&Expr::String("a\"b\\c".into())).as_deref(),
            Some("\"a\\\"b\\\\c\"")
        );
        assert_eq!(render_simple_expr(&Expr::Tuple(Vec::new())), None);
        let error =
            analyze_error("fn f(NftId token, AccountId who) { ledger::nft::mint(token, who); }");
        assert_eq!(error.code, "E_NAMED_ARGUMENTS_REQUIRED");
        assert!(
            error.message.ends_with("pass a variable named `nft`"),
            "{}",
            error.message
        );
        let error =
            analyze_error("fn f(NftId nft, AccountId owner) { ledger::nft::mint(owner, nft); }");
        assert_eq!(
            error.code, "E_NAMED_ARGUMENTS_REQUIRED",
            "punning follows the slot"
        );
        // A pun in another parameter's slot is named as such instead of
        // asking for a variable the call already passes.
        assert!(
            error
                .message
                .contains("`owner` is spelled like parameter `owner`"),
            "{}",
            error.message
        );
        assert!(
            !error.message.contains("pass a variable named"),
            "{}",
            error.message
        );
        // The fix for a swapped call labels each identifier by its own name
        // instead of encoding the swap.
        let swapped = parse("fn f(NftId nft, AccountId owner) { ledger::nft::mint(owner, nft); }")
            .expect("parse swapped call");
        let Item::Function(function) = &swapped.items[0] else {
            panic!("function");
        };
        let Statement::Expr(call) = function.body.statements[0].kind() else {
            panic!("call statement");
        };
        let Expr::Call {
            args,
            argument_names,
            ..
        } = call.kind()
        else {
            panic!("call");
        };
        assert_eq!(
            labelled_builtin_call_fix(
                "ledger::nft::mint",
                args,
                argument_names.as_deref(),
                &["nft".to_owned(), "owner".to_owned()],
            )
            .as_deref(),
            Some("ledger::nft::mint(owner: owner, nft: nft)")
        );
    }
    #[test]
    fn kotoage_and_views_may_use_builtin_lowering_names() {
        analyze(
            &parse("seiyaku Names { permission Mint;  kotoage fn mint_asset() authorize(Mint) {} view fn chain_id() authorize(anyone) -> int { 1 } view fn authority() authorize(anyone) -> int { 2 } }")
                .expect("parse public selectors"),
        )
        .expect("public selectors may reuse lowering names");
        analyze(&parse("fn min(int a, int b) -> int { a }").expect("private declaration parses"))
            .expect("private helpers also have independent call identities");
    }
    analyze_ok_tests! { label_punning_satisfies_required_builtin_labels: "fn main(AccountId account, Name key, Json value) { ledger::account::set_metadata(account, key, value); }" => "parse punned call", "identifiers spelled like the labels are labelled arguments"; }
    analyze_ok_tests! { declared_builtin_labels_are_always_accepted: "fn main(int amount) -> int { return math::min(left: math::abs(value: amount), right: 3); }" => "parse labelled pure helpers", "a label equal to the declared name is accepted"; }
    analyze_ok_tests! { pure_math_helpers_accept_positional_arguments: "fn main(int amount) -> int { return math::div_ceil(math::max(amount, 1), 2); }" => "parse positional pure helpers", "pure helpers accept positional arguments"; }
    #[test]
    fn offset_state_enumeration_is_not_a_source_api() {
        for source in [
            "fn page(bytes path) -> bytes { return state::keys(path: path, offset: 0, limit: 10); }",
            "fn page(bytes path) -> bytes { return state_keys(path: path, offset: 0, limit: 10); }",
        ] {
            let error = analyze_error(source);
            assert!(error.message.contains("state"), "{error:?}");
        }
    }
    #[test]
    fn durable_state_calls_reject_legacy_name_path_carriers() {
        for source in [
            "fn read() { let _value = state::get(Name::parse(\"legacy\")); }",
            "fn write(bytes value) { state::set(path: Name::parse(\"legacy\"), value: value); }",
            "fn delete() { state::delete(Name::parse(\"legacy\")); }",
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, "K2003", "{source}");
            assert!(
                error.message.contains("bytes StatePath"),
                "{source}: {}",
                error.message
            );
        }
        let canonical = parse(
            "fn read(Name base) -> bytes { let bytes path = base.path(1); return state::get(path); }",
        )
        .expect("parse StatePath-producing helper");
        analyze(&canonical).expect("base.path must produce a state-call-compatible bytes value");
    }
    #[test]
    fn state_path_method_rejects_wrong_receiver_and_segment_types() {
        for source in [
            "fn invalid(string base) { let _path = base.path(1); }",
            "fn invalid(Name base) { let _path = base.path(json { bad: true }); }",
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, "K2003", "{source}");
            assert_eq!(
                error.message, "path expects a Name and a canonical scalar or tuple StateMap key",
                "{source}"
            );
        }
    }
    #[test]
    fn duplicate_top_level_declarations_are_rejected() {
        let cases = [
            (
                "fn repeated() {} fn repeated() {}",
                "duplicate function `repeated`",
            ),
            (
                "struct Repeated { int value; } struct Repeated { int value; }",
                "duplicate type `Repeated`",
            ),
            (
                "state int repeated; state int repeated;",
                "duplicate state `repeated`",
            ),
            (
                "const int repeated = 1; const int repeated = 2;",
                "duplicate const `repeated`",
            ),
        ];
        for (source, expected) in cases {
            let err = analyze_error(source);
            assert_eq!(err.message, expected);
        }
    }
    analyze_error_code_message_tests! { cross_kind_declaration_collisions_are_rejected: err = "struct Shared { int value; } fn Shared() {}" => "E_DUPLICATE_DECLARATION", "declaration name `Shared` is already used by a type"; }
    #[test]
    fn compiler_owned_declaration_names_are_rejected() {
        for (source, expected) in [
            (
                "fn __kotodama_link_private() {}",
                "function `__kotodama_link_private` uses a compiler-reserved name",
            ),
            (
                "struct Option { int value; }",
                "type `Option` uses a compiler-reserved name",
            ),
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, "E_RESERVED_DECLARATION");
            assert_eq!(error.message, expected);
        }
    }
    #[test]
    fn duplicate_function_parameters_are_rejected() {
        let err = analyze_error("fn repeated(int value, bool value) {}");
        assert_eq!(
            err.message,
            "duplicate parameter `value` in function `repeated`"
        );
    }
    #[test]
    fn duplicate_struct_fields_are_rejected() {
        let err = analyze_error("struct Repeated { int value; bool value; }");
        assert_eq!(err.message, "duplicate field `value` in type `Repeated`");
    }
    #[test]
    fn variant_codes_are_enum_local_and_require_is_typed() {
        let duplicates = parse(
            "error enum Payment { Unauthorized = 1001 } \
             error enum Settlement { Expired = 1001 }",
        )
        .expect("enum-local codes parse");
        analyze(&duplicates).expect("distinct nominal enums may share raw codes");
        let accepted = parse(
            "error enum Payment { Unauthorized = 1001 } \
             fn pay(bool allowed) { require(allowed, Payment::Unauthorized); }",
        )
        .expect("parse typed require");
        let typed = analyze(&accepted).expect("declared error variant is accepted");
        let payment = typed
            .error_types
            .iter()
            .find(|descriptor| descriptor.identity == format!("{}::Payment", typed.unit.name))
            .expect("exact Payment nominal descriptor");
        assert_eq!(payment.variants.len(), 1);
        assert_eq!(payment.variants[0].name, "Unauthorized");
        assert_eq!(payment.variants[0].code, 1001);
        for invalid in [
            "require(true);",
            "require(true, 1001);",
            "require(true, \"unauthorized\");",
            "require(true, Payment::Missing);",
        ] {
            let program = parse(&format!(
                "error enum Payment {{ Unauthorized = 1001 }} fn pay() {{ {invalid} }}"
            ))
            .expect("invalid require shape still parses");
            let error = analyze(&program).expect_err("untyped require must fail");
            assert!(
                error.message.contains("require")
                    || error.message.contains("error variant")
                    || error.message.contains("Payment::Missing"),
                "unexpected error for `{invalid}`: {error:?}"
            );
        }
    }
    #[test]
    fn semantic_analysis_rejects_ast_parameters_without_types() {
        let mut program = parse("fn f(int value) {}").expect("parse typed parameter");
        let Item::Function(function) = &mut program.items[0] else {
            panic!("expected function")
        };
        function.params[0].ty = None;
        let err = analyze(&program).expect_err("typeless parameter AST must be rejected");
        assert_eq!(err.message, "parameter `value` requires an explicit type");
    }
    #[test]
    fn semantic_analysis_rejects_ast_consts_without_types() {
        let mut program = parse("const int VALUE = 1;").expect("parse typed const");
        let Item::Const(declaration) = &mut program.items[0] else {
            panic!("expected const")
        };
        declaration.ty = None;
        let err = analyze(&program).expect_err("typeless const AST must be rejected");
        assert_eq!(err.message, "const `VALUE` requires an explicit type");
    }
    #[test]
    fn unknown_path_and_generic_types_are_rejected() {
        let path_err = analyze_error("fn use_missing(Missing value) {}");
        assert_eq!(path_err.message, "unknown type `Missing`");
        let generic_err = analyze_error("fn generic(Missing<int> value) {}");
        assert_eq!(generic_err.message, "unknown generic type `Missing`");
    }
    #[test]
    fn opaque_host_capability_types_are_not_source_types() {
        for name in [
            "AxtDescriptor",
            "AxtAnchoredSpendV1",
            "ProofBlob",
            "SoracloudRequest",
            "SoracloudResponse",
        ] {
            let error = analyze_error(&format!("fn f({name} value) {{}}"));
            assert_eq!(error.message, format!("unknown type `{name}`"));
        }
    }
    #[test]
    fn option_and_result_type_expressions_are_recognized() {
        let context = SemanticContext::new();
        let option = TypeExpr::Generic {
            base: "Option".into(),
            args: vec![TypeExpr::Path("int".into())],
        };
        assert_eq!(
            convert_type_expr(&context, &option).expect("Option type"),
            Type::Option(Box::new(Type::Int))
        );
        let result = TypeExpr::Generic {
            base: "Result".into(),
            args: vec![TypeExpr::Path("int".into()), TypeExpr::Path("bool".into())],
        };
        assert_eq!(
            convert_type_expr(&context, &result).expect("Result type"),
            Type::Result(Box::new(Type::Int), Box::new(Type::Bool))
        );
        let helpers = parse(
            "fn option_helper(Option<int> value) {} \
             fn result_helper(Result<int, bool> value) { let _ = value; }",
        )
        .expect("private helper types parse");
        analyze(&helpers).expect("private helpers accept Option/Result parameters");
        let public = parse(
            "seiyaku Demo { permission Call;  kotoage fn call(Option<int> value, Result<int, bool> outcome) authorize(Call) { let _ = outcome; } }",
        )
        .expect("public sum parameters parse");
        analyze(&public).expect("one-shot V1 argument records support Option and Result");
        let unsupported = analyze_error(
            "seiyaku Demo { permission Call;  kotoage fn call(StateMap<int, int> value) authorize(Call) {} }",
        );
        assert!(
            unsupported
                .message
                .contains("unsupported V1 boundary type `StateMap<int, int>`"),
            "unexpected error: {}",
            unsupported.message
        );
    }
    #[rustfmt::skip]
    analyze_ok_tests! { forward_declared_struct_types_are_accepted: "struct First { Second second; } \
             struct Second { int value; } \
             fn read(First first) -> int { return first.second.value; }" => "source should parse", "forward-declared struct references should resolve"; }
    #[test]
    fn reusable_context_clears_all_declaration_registries() {
        let context = SemanticContext::new();
        let declared = parse(
            "struct SessionOnly { int value; } \
             fn read(SessionOnly value) -> int { return value.value; }",
        )
        .expect("declared source");
        context.analyze(&declared).expect("first analysis");
        let undeclared = parse("fn read(SessionOnly value) -> int { return value.value; }")
            .expect("undeclared source parses");
        let error = context
            .analyze(&undeclared)
            .expect_err("the previous source's type must not leak");
        assert_eq!(error.message, "unknown type `SessionOnly`");
        context
            .analyze(&declared)
            .expect("context remains reusable after a failed analysis");
    }
    #[test]
    fn internal_named_struct_references_are_nominal() {
        let alpha = Type::NamedStruct("Alpha".to_string());
        let another_alpha = Type::NamedStruct("Alpha".to_string());
        let beta = Type::NamedStruct("Beta".to_string());
        ensure_assignable(&alpha, &another_alpha)
            .expect("same named struct reference should be assignable");
        let err = ensure_assignable(&alpha, &beta)
            .expect_err("unrelated named struct references must not be assignable");
        assert!(err.message.contains("expected `Alpha`, found `Beta`"));
    }
    #[test]
    fn cyclic_value_structs_are_rejected_before_resolution() {
        let direct = analyze_error("struct Node { Node next; } state Node root;");
        assert_eq!(
            direct.message,
            "cyclic value struct definition: Node -> Node"
        );
        let indirect = analyze_error(
            "struct Left { Right right; } \
             struct Right { Left left; } \
             state Left root;",
        );
        assert_eq!(
            indirect.message,
            "cyclic value struct definition: Left -> Right -> Left"
        );
    }
    #[test]
    fn get_private_input_requires_build_configured_zk_mode() {
        let err = analyze_error("fn read() -> int { return crypto::private_input(0); }");
        assert_eq!(
            err.message,
            "builtin `crypto::private_input` requires ZK mode in compiler build configuration"
        );
        let source = include_str!("semantic/fixtures/v1/s001.ko");
        let program = parse(source).expect("ZK-enabled source should parse");
        SemanticContext::with_zk_enabled(true)
            .analyze(&program)
            .expect("build-configured ZK mode should permit private input access");
    }
    #[test]
    fn return_type_match() {
        let ok1 = analyze(&parse("fn f() -> bool { return true; } ").unwrap());
        assert!(ok1.is_ok());
        let ok2 = analyze(&parse("fn g() -> int { return 1; } ").unwrap());
        assert!(ok2.is_ok());
        let ok3 = analyze(&parse("fn h() { return; } ").unwrap());
        assert!(ok3.is_ok());
    }
    #[test]
    fn return_type_mismatch() {
        let err = analyze(&parse("fn f() -> bool { return 1; } ").unwrap());
        assert!(err.is_err());
        let err2 = analyze(&parse("fn h() { return 1; } ").unwrap());
        assert!(err2.is_err());
    }
    #[test]
    fn non_unit_must_return_all_paths() {
        let err = analyze(&parse("fn f() -> int { if true { return 1; } } ").unwrap());
        assert!(err.is_err());
        let ok =
            analyze(&parse("fn g() -> int { if true { return 1; } else { return 2; } } ").unwrap());
        assert!(ok.is_ok());
    }
    #[test]
    fn return_value_requires_declared_type() {
        let err = analyze(&parse("fn f() { return 1; } ").unwrap());
        assert!(err.is_err());
        let ok = analyze(&parse("fn g() { return; } ").unwrap());
        assert!(ok.is_ok());
    }
    #[test]
    fn param_type_enforcement_primitives() {
        // Boolean-to-integer coercion is intentionally absent from V1.
        let bool_arithmetic = analyze(&parse("fn f(bool x) { let y = x + 1; } ").unwrap());
        assert!(bool_arithmetic.is_err());
        // string param cannot be used in arithmetic
        let err2 = analyze(&parse("fn g(string s) { let y = s + 1; } ").unwrap());
        assert!(err2.is_err());
        // Canonical parameters always declare their type.
        let ok = analyze(&parse("fn h(int x, int y) -> int { return x + y; } ").unwrap());
        assert!(ok.is_ok());
    }
    #[test]
    fn typed_id_parameters_reject_arithmetic() {
        // Typed ledger identifiers are not numeric.
        let err = analyze(&parse("fn f(AccountId who) { let y = who + 1; } ").unwrap());
        assert!(err.is_err());
        // Equality on same named struct references is allowed
        let ok =
            analyze(&parse("fn g(AccountId a, AccountId b) -> bool { return a == b; } ").unwrap());
        assert!(ok.is_ok());
    }
    #[test]
    fn tuple_bindings_flatten_members() {
        let program = parse("fn f() { let pair = (1, 2); } ").unwrap();
        let typed = analyze(&program).expect("analysis ok");
        let TypedItem::Function(func) = &typed.items[0];
        let names: Vec<String> = func
            .body
            .statements
            .iter()
            .filter_map(|stmt| match stmt {
                TypedStatement::Let { name, .. } => Some(name.clone()),
                _ => None,
            })
            .collect();
        let suffixes: Vec<String> = names
            .into_iter()
            .map(|name| name.rsplit("::").next().unwrap().to_string())
            .collect();
        assert_eq!(suffixes, vec!["pair", "pair#0", "pair#1"]);
    }
    #[test]
    fn struct_destructuring_uses_field_names_for_out_of_order_literals() {
        let program = parse(
            "struct Pair { int first, string second } \
             fn f() { \
                 let pair = Pair { second: \"two\", first: 1 }; \
                 let Pair { second: right, first: left } = Pair { second: \"four\", first: 3 }; \
             }",
        )
        .expect("parse named struct literals");
        let typed = analyze(&program).expect("analyze named struct literals");
        let TypedItem::Function(function) = &typed.items[0];
        let binding = |suffix: &str| {
            function
                .body
                .statements
                .iter()
                .find_map(|statement| match statement {
                    TypedStatement::Let { name, value }
                        if name.rsplit("::").next() == Some(suffix) =>
                    {
                        Some(value)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing binding `{suffix}`"))
        };
        let is_projection = |value: &TypedExpr, base: Option<&str>, index: &str| {
            matches!(
                &value.expr,
                ExprKind::Member { object, field }
                    if field == index
                        && matches!(
                            object.kind(),
                            ExprKind::Ident(name)
                                if base.is_none_or(|base| {
                                    name.rsplit("::").next() == Some(base)
                                })
                        )
            )
        };
        assert!(is_projection(binding("pair#0"), Some("pair"), "0"));
        assert!(is_projection(binding("pair#1"), Some("pair"), "1"));
        assert!(is_projection(binding("left"), None, "0"));
        assert!(is_projection(binding("right"), None, "1"));
    }
    #[rustfmt::skip]
    analyze_ok_tests! { state_map_iteration_accepts_pointer_keys: "state StateMap<Name, int> Items; \
             fn main() { \
                 for (k, v) in Items.take(1) { \
                     let _x = v; \
                 } \
             }" => "parse state map", "canonical StateMap iteration supports typed pointer keys"; }
    #[test]
    fn static_state_map_iteration_limit_is_inclusive_and_fail_closed() {
        for iteration in ["M.take(64)", "M.page(after: Option::none, limit: 64).items"] {
            let program = parse(&format!(
                "state StateMap<int, int> M; \
                 fn main() {{ for (key, value) in {iteration} {{ let _value = value; }} }}"
            ))
            .expect("boundary iteration source parses");
            analyze(&program).unwrap_or_else(|error| {
                panic!("boundary iteration `{iteration}` must be accepted: {error:?}")
            });
        }
        for iteration in ["M.take(65)", "M.page(after: Option::none, limit: 65).items"] {
            let program = parse(&format!(
                "state StateMap<int, int> M; \
                 fn main() {{ for (key, value) in {iteration} {{ let _value = value; }} }}"
            ))
            .expect("over-limit iteration source parses");
            let error = analyze(&program).expect_err("bound above 64 must fail semantically");
            assert_eq!(error.code, "E_ITERATION_LIMIT");
            assert_eq!(error.message, "collection limit must be in 1..=64");
        }
    }
    #[test]
    fn dynamic_map_take_rejects_runtime_bounds() {
        let program = parse(
            "state StateMap<int, int> M; \
             fn main(int n) { \
                 for (k, v) in M.take(n) { \
                     let _x = v; \
                 } \
             }",
        )
        .expect("parse dynamic take");
        let error = analyze(&program).expect_err("dynamic take must fail closed in V1");
        assert!(
            error
                .message
                .contains("compile-time int constant expression")
        );
    }
    #[rustfmt::skip]
    analyze_reject_contains_tests! { offset_map_range_is_not_source_syntax: "state StateMap<int, int> M; \
             fn main(int start, int end) { \
                 for (k, v) in M.range(start, end) { \
                     let _x = v; \
                 } \
             }" => "parse removed range method", error = "offset map ranges are unsupported", "range"; }
    #[rustfmt::skip]
    analyze_reject_code_tests! { state_map_alias_is_rejected: "state StateMap<int, int> M; \
             fn main() { \
                 let m = M; \
             }" => "parse state map alias", err = "aliasing a state map should error", "E_STATE_MAP_ALIAS"; }
    #[rustfmt::skip]
    analyze_reject_code_tests! { state_map_reassignment_is_rejected: "state StateMap<int, int> M; \
             fn main() { \
                 M = StateMap::new(); \
             }" => "parse state map reassignment", err = "reassigning a state map should error", "E_STATE_MAP_ALIAS"; }
    #[rustfmt::skip]
    analyze_reject_code_tests! { state_map_cannot_be_passed_to_user_fn: "state StateMap<int, int> M; \
             fn f(StateMap<int, int> m) { let _x = 0; } \
             fn main() { f(m: M); }" => "parse state map arg", err = "passing state map to user fn should error", "E_STATE_MAP_ALIAS"; }
    analyze_error_code_message_tests! { scalar_state_requires_hajimari: err = "state int counter; fn read() -> int { return counter; }" => "E_STATE_HAJIMARI_REQUIRED", "seiyaku scalar state requires a `hajimari()`/`始まり()` declaration"; }
    analyze_error_code_message_tests! { scalar_state_hajimari_reports_every_missing_write: err = "state int first; state int second; hajimari() { first = 0; }" => "E_STATE_HAJIMARI_INCOMPLETE", "hajimari() must initialize every scalar state on every normal return or fallthrough path; missing: second"; }
    #[test]
    fn scalar_state_initialization_intersects_conditional_paths() {
        let accepted = parse(
            "state int value; \
             hajimari() { if true { value = 1; } else { value = 2; } }",
        )
        .expect("parse complete conditional hajimari");
        analyze(&accepted).expect("both conditional paths initialize scalar state");
        let err = analyze_error(
            "state int value; \
             hajimari() { if true { value = 1; } }",
        );
        assert_eq!(err.code, "E_STATE_HAJIMARI_INCOMPLETE");
    }
    #[test]
    fn scalar_state_initialization_checks_early_returns() {
        let err = analyze_error(
            "state int value; \
             hajimari() { if true { return; } value = 1; }",
        );
        assert_eq!(err.code, "E_STATE_HAJIMARI_INCOMPLETE");
        let accepted = parse(
            "state int value; \
             hajimari() { if true { value = 1; return; } value = 2; }",
        )
        .expect("parse initialized early return");
        analyze(&accepted).expect("every normal exit initializes scalar state");
    }
    #[test]
    fn scalar_state_initialization_checks_early_returns_inside_expressions() {
        for source in [
            "state int value; \
             hajimari() { \
                 let int ignored = if true { return; } else { 0 }; \
                 value = 1; \
             }",
            "state int value; \
             hajimari() { \
                 let int ignored = match Option::some(1) { \
                     Option::some(item) => { return; }, \
                     Option::none => { 0 } \
                 }; \
                 value = 1; \
             }",
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, "E_STATE_HAJIMARI_INCOMPLETE");
            assert!(error.message.contains("missing: value"));
        }

        let initialized = parse(
            "state int value; \
             hajimari() { \
                 let int ignored = if true { \
                     value = 1; \
                     return; \
                 } else { \
                     value = 1; \
                     0 \
                 }; \
             }",
        )
        .expect("parse expression branches that initialize state");
        analyze(&initialized).expect("state writes before expression exits must remain definite");
    }
    #[rustfmt::skip]
    analyze_error_code_cases! {
        scalar_state_initialization_does_not_trust_optional_execution:
        loop_error = "state int value; \
             hajimari() { for index in range(1) { value = index; } }" => "E_STATE_HAJIMARI_INCOMPLETE";
        short_circuit_error = "state int value; \
             fn seed() -> bool { value = 1; return true; } \
             hajimari() { let ignored = false && seed(); }" => "E_STATE_HAJIMARI_INCOMPLETE";
    }
    #[rustfmt::skip]
    analyze_ok_tests! { scalar_state_hajimari_accepts_transitive_complete_initialization: "state int counter; \
             struct Ledger { int total; } \
             state Ledger ledger; \
             fn seed() { counter = 0; ledger = Ledger { total: 0 }; } \
             hajimari() { seed(); }" => "parse transitive scalar hajimari", "transitive hajimari writes should initialize every scalar state"; }
    analyze_reject_contains_tests! { map_assignment_requires_map_target: "fn f() { let x = 1; x[0] = 2; }" => "parse map assignment", err = "non-map assignment should error", "map assignment expects StateMap<K,V>"; }
    #[test]
    fn assignment_rejects_bool_to_int() {
        let program =
            parse("fn f() { var int x = true; x = false; }").expect("parse bool assignment");
        analyze(&program).expect_err("bool assignment must not coerce to int");
    }
    analyze_error_code_message_tests! { immutable_local_reassignment_is_rejected: err = "fn f() { let value = 1; value = 2; }" => "E_IMMUTABLE_ASSIGNMENT", "cannot assign to immutable binding `value`; declare a mutable local with `var`"; }
    analyze_ok_tests! { mutable_local_reassignment_is_accepted: "fn f() -> int { var value = 1; value += 2; return value; }" => "parse mutable binding", "var bindings should permit reassignment"; }
    analyze_error_code_message_tests! { function_parameters_are_immutable: err = "fn f(int value) { value = 2; }" => "E_IMMUTABLE_ASSIGNMENT", "cannot assign to immutable binding `value`; declare a mutable local with `var`"; }
    #[test]
    fn local_declarations_cannot_duplicate_or_shadow_bindings() {
        for source in [
            "fn f() { let value = 1; let value = 2; }",
            "fn f(int value) { let value = 2; }",
            "fn f() { let (left, left) = (1, 2); }",
        ] {
            analyze_error(source);
        }
    }
    #[test]
    fn parameters_and_locals_cannot_shadow_any_source_declaration() {
        for source in [
            "seiyaku App { fn helper() {} fn inspect(int helper) {} }",
            "seiyaku App { struct Receipt { int value; } fn inspect() { let Receipt = 1; } }",
            "seiyaku App { fn inspect() { let App = 1; } }",
        ] {
            let program = parse(source).expect("parse global shadowing fixture");
            let error = analyze(&program).expect_err("global shadowing must be rejected");
            assert!(
                error.message.contains("shadows a source declaration"),
                "unexpected shadowing error for {source}: {error:?}"
            );
        }
    }
    #[test]
    fn source_unit_identity_cannot_be_redeclared_inside_the_unit() {
        let program = parse("seiyaku App { fn App() {} }").expect("parse identity collision");
        let error = analyze(&program).expect_err("unit identity collision must be rejected");
        assert!(
            error.message.contains("already used by a source unit"),
            "{error:?}"
        );
    }
    analyze_reject_code_tests! { break_requires_loop_context: "fn f() { break; }" => "parse break", err = "break outside loop should error", "E_BREAK_OUTSIDE_LOOP"; }
    analyze_reject_code_tests! { continue_requires_loop_context: "fn f() { continue; }" => "parse continue", err = "continue outside loop should error", "E_CONTINUE_OUTSIDE_LOOP"; }
    analyze_reject_code_tests! { state_shadowing_is_rejected_in_let: "state int counter; fn f() { let counter = 1; }" => "parse shadowing let", err = "state shadowing should error", "E_STATE_SHADOWED"; }
    analyze_reject_code_tests! { state_shadowing_is_rejected_in_params: "state int counter; fn f(int counter) {}" => "parse shadowing param", err = "state shadowing should error", "E_STATE_SHADOWED"; }
    #[rustfmt::skip]
    analyze_reject_code_tests! { state_shadowing_is_rejected_in_map_loop_vars: "state int counter; state StateMap<int, int> M; \
             fn f() { for (counter, v) in M.take(1) { let _x = v; } }" => "parse shadowing loop vars", err = "state shadowing should error", "E_STATE_SHADOWED"; }
    #[test]
    fn c_style_for_is_rejected_before_semantic_analysis() {
        for source in [
            "fn f() { for let pair = (1, 2); pair.0 < 3; {} }",
            "fn f() { for let i = 0; i < 1; let pair = (1, 2) {} }",
        ] {
            let err = parse(source).expect_err("C-style loops are outside the V1 surface");
            assert!(err.contains("for pattern in collection"), "{err}");
        }
    }
    #[test]
    fn manually_constructed_while_ast_cannot_bypass_v1_frontend_rules() {
        let mut program = parse("fn f() {}").expect("parse base program");
        let Item::Function(function) = &mut program.items[0] else {
            panic!("expected function item");
        };
        function.body.statements.push(Statement::While {
            cond: Expr::Bool(true),
            body: Block {
                statements: Vec::new(),
                tail: None,
            },
        });
        let error = analyze(&program).expect_err("while AST must fail closed");
        assert_eq!(error.code, "E_UNBOUNDED_LOOP");
    }
    #[test]
    fn manually_constructed_dynamic_for_ast_cannot_bypass_v1_frontend_rules() {
        let mut program = parse("fn f() {}").expect("parse base program");
        let Item::Function(function) = &mut program.items[0] else {
            panic!("expected function item");
        };
        function.body.statements.push(Statement::For {
            line: 1,
            init: Some(Box::new(Statement::Let {
                mutable: true,
                pat: Pattern::Name("i".to_owned()),
                ty: None,
                value: Expr::IntLiteral(BigInt::zero()),
            })),
            cond: Some(Expr::Binary {
                op: BinaryOp::Lt,
                left: Box::new(Expr::Ident("i".to_owned())),
                right: Box::new(Expr::Ident("dynamic_bound".to_owned())),
            }),
            step: Some(Box::new(Statement::Assign {
                name: "i".to_owned(),
                value: Expr::Binary {
                    op: BinaryOp::Add,
                    left: Box::new(Expr::Ident("i".to_owned())),
                    right: Box::new(Expr::IntLiteral(BigInt::one())),
                },
            })),
            body: Block {
                statements: Vec::new(),
                tail: None,
            },
        });
        let error = analyze(&program).expect_err("dynamic for AST must fail closed");
        assert_eq!(error.code, "E_UNBOUNDED_LOOP");
    }
    analyze_ok_tests! { equality_accepts_tuple_types: "fn f() { let a = (1, 2); let b = (1, 2); let _x = a == b; }" => "parse tuple equality", "tuple equality should be allowed"; }
    analyze_ok_tests! { pointer_constructor_accepts_string_binding: "fn f() { let s = \"wonderland\"; let _n = Name::parse(s); }" => "parse pointer constructor", "string binding should be allowed"; }
    #[test]
    fn flat_pointer_constructor_spellings_are_rejected() {
        for (flat, canonical) in [
            ("account_id", "AccountId::parse"),
            ("asset_definition", "AssetDefinitionId::parse"),
            ("asset_id", "AssetId::parse"),
            ("nft_id", "NftId::parse"),
            ("name", "Name::parse"),
            ("json", "Json::parse"),
            ("domain_id", "DomainId::parse"),
            ("dataspace_id", "DataSpaceId::parse"),
        ] {
            let source = format!("fn f() {{ let _value = {flat}(\"x\"); }}");
            let program = parse(&source).expect("flat builtin call parses before resolution");
            let error = analyze(&program).expect_err("flat builtin spelling must fail closed");
            assert!(
                error
                    .message
                    .contains("legacy or non-canonical builtin spelling"),
                "{error:?}"
            );
            assert!(error.message.contains(canonical), "{error:?}");
        }
    }
    #[test]
    fn flat_builtin_spellings_are_rejected_in_favour_of_namespaces() {
        for (flat_call, canonical) in [
            ("wrapping_add(left: 1, right: 2)", "math::wrapping_add"),
            ("info(1)", "debug::info"),
            ("assert(true)", "test::assert"),
            ("assert_eq(actual: 1, expected: 1)", "test::assert_eq"),
            ("actor_account(\"issuer\")", "test::actor_account"),
            (
                "invoke_entrypoint(\"run\", Json::parse(\"{}\"))",
                "test::invoke_kotoage",
            ),
            ("trigger_event()", "context::trigger_event"),
        ] {
            let source = format!("fn f() {{ let _value = {flat_call}; }}");
            let program = parse(&source).expect("flat builtin call parses before resolution");
            let error = SemanticContext::with_capabilities(false, true)
                .analyze(&program)
                .expect_err("flat builtin spelling must fail closed");
            assert!(
                error
                    .message
                    .contains("legacy or non-canonical builtin spelling"),
                "{error:?}"
            );
            assert!(error.message.contains(canonical), "{error:?}");
        }
    }
    analyze_ok_tests! { japanese_branded_capability_segments_normalize_to_the_canonical_registry: include_str!("semantic/test_sources/japanese_branded_capability_segments_normalize_to_the_canonical_registry_1.ko") => "parse Japanese branded capability path", "Japanese capability segments must resolve canonically"; }
    #[test]
    fn canonical_builtin_diagnostics_replace_only_identifier_tokens() {
        assert_eq!(
            replace_identifier_token(
                "info expects a value; compiler configuration is unchanged",
                "info",
                "debug::info",
            ),
            "debug::info expects a value; compiler configuration is unchanged"
        );
        assert_eq!(
            replace_identifier_token(
                "my_invoke_entrypoint_helper targets invoke_entrypoint",
                "invoke_entrypoint",
                "test::invoke_kotoage",
            ),
            "my_invoke_entrypoint_helper targets test::invoke_kotoage"
        );
    }
    #[rustfmt::skip]
    analyze_reject_contains_tests! { for_body_bindings_do_not_escape_loop: "fn f() { \
                for i in range(1) { \
                    let x = 1; \
                } \
                let _y = x; \
            }" => "parse for loop", err = "body bindings should not escape", "undefined variable"; }
    analyze_reject_contains_tests! { tuple_pattern_requires_tuple_type: "fn f() { let (a, b) = 1; }" => "parse tuple pattern", err = "non-tuple destructuring should error", "tuple destructuring expects a tuple"; }
    #[test]
    fn tuple_pattern_requires_arity_match() {
        let program = parse("fn f() { let (a, b, c) = (1, 2); }").expect("parse tuple pattern");
        let err = analyze(&program).expect_err("tuple arity mismatch should error");
        assert!(
            err.message
                .contains("tuple destructuring expects 2 bindings")
        );
    }
    #[test]
    fn struct_pattern_requires_explicit_missing_field_discard() {
        let program = parse(
            "struct Pair { int a, int b } \
             fn f() { let Pair { a } = Pair { a: 1, b: 2 }; }",
        )
        .expect("parse struct pattern");
        let err = analyze(&program).expect_err("missing fields require an explicit rest marker");
        assert_eq!(err.code, "E_MISSING_STRUCT_PATTERN_FIELD");
    }
    #[test]
    fn assert_eq_compares_any_equality_type_and_accepts_typed_argument_records() {
        let accepted = parse(
            r#"seiyaku S {
                struct P { int a, string b }
                fn f() {
                    test::assert_eq(actual: P { a: 1, b: "x" }, expected: P { a: 1, b: "x" }, message: "same");
                    test::assert_eq(actual: 1.5, expected: 1.5);
                    test::assert_eq(actual: "x", expected: "x");
                    test::assert(true, message: 7);
                }
            }"#,
        )
        .expect("parse generic assertions");
        SemanticContext::with_capabilities(false, true)
            .analyze(&accepted)
            .expect("assert_eq accepts every equality-comparable type");
        let mismatched = parse(r#"fn f() { test::assert_eq(actual: 1, expected: "x"); }"#)
            .expect("parse mismatched assertion");
        let err = SemanticContext::with_capabilities(false, true)
            .analyze(&mismatched)
            .expect_err("operands of different types are rejected");
        assert!(
            err.message
                .contains("compares `actual` and `expected` of one type, found `int` and `string`"),
            "{}",
            err.message
        );
        let record = parse(
            r#"seiyaku S { permission Run;
                kotoage fn run(int count) authorize(Run) {}
                #[test] fn t() {
                    test::invoke_kotoage(kotoage: "run", arguments: {count: 3});
                }
            }"#,
        )
        .expect("parse literal record");
        SemanticContext::with_capabilities(false, true)
            .analyze(&record)
            .expect("native int expressions are typed against the target parameter");
    }
    #[test]
    fn typed_test_argument_records_preserve_exact_nominal_parameter_types() {
        let source = |record: &str| {
            format!(
                r#"seiyaku Typed {{
            enum Status {{ Active = 1 }}
            enum Other {{ Active = 1 }}
            struct Record {{ Status status; }}
            view fn echo(Record value, Option<Status> previous) authorize(anyone) -> Record {{ value }}
            #[test] fn t() {{ test::invoke_kotoage(kotoage: "echo", arguments: {record}); }}
        }}"#
            )
        };
        let valid = parse(&source(
            "{ previous: Option::none, value: Record { status: Status::Active } }",
        ))
        .unwrap();
        SemanticContext::with_capabilities(false, true)
            .analyze(&valid)
            .expect("exact nominal source values");
        for record in [
            "{ previous: Option::none, value: Record { status: Other::Active } }",
            "{ value: Record { status: Status::Active } }",
            "{ previous: Option::none, value: Record { status: Status::Active }, extra: 1 }",
            "Json::parse(\"{}\")",
        ] {
            let program = parse(&source(record)).unwrap();
            let error = SemanticContext::with_capabilities(false, true)
                .analyze(&program)
                .unwrap_err();
            assert_eq!(error.code, "E_TEST_ARGUMENT_RECORD", "{record}: {error:?}");
        }
    }
    #[test]
    fn unknown_invocation_targets_and_argument_keys_get_spelling_hints() {
        let analyze = |test_body: &str| {
            let source = format!(
                r#"seiyaku S {{ permission Teller;
                    state int value;
                    始まり(int start) {{ value = start; }}
                    kotoage fn withdraw(int amount) authorize(Teller) {{ value = value - amount; }}
                    #[test] fn t() {{ {test_body} }}
                }}"#
            );
            let program = parse(&source).expect("parse invocation fixture");
            SemanticContext::with_capabilities(false, true)
                .analyze(&program)
                .expect_err("invalid invocation")
        };
        // A lifecycle keyword written as a selector, in either script, names the selector.
        let err = analyze(r#"test::invoke_kotoage(kotoage: "始まり", arguments: {start: 1});"#);
        assert_eq!(err.code, "K2002");
        assert_eq!(
            err.message,
            "`始まり` is a lifecycle keyword, not a selector; the `始まり` declaration is selected as \"hajimari\""
        );
        let err = analyze(r#"test::invoke_kotoage(kotoage: "withdrw", arguments: {});"#);
        assert!(
            err.message.ends_with("; did you mean \"withdraw\"?"),
            "{}",
            err.message
        );
        let err = analyze(r#"test::invoke_kotoage(kotoage: "hajimari", arguments: {strat: 1});"#);
        assert!(
            err.message
                .ends_with("`strat` is not a parameter; did you mean `start`?"),
            "{}",
            err.message
        );
    }
    #[test]
    fn test_helper_calls_gain_a_trailing_call_site_record() {
        let context = SemanticContext::with_capabilities(false, true);
        let literal = |text: &str| TypedExpr {
            expr: ExprKind::String(text.to_owned()),
            ty: Type::String,
        };
        let decode_site = |typed: &TypedExpr| match typed.kind() {
            ExprKind::Bytes(bytes) => {
                norito::decode_canonical::<crate::testing::TestCallSite>(bytes)
                    .expect("canonical call-site record")
            }
            other => panic!("expected a call-site literal, found {other:?}"),
        };
        let named = TypedExpr {
            expr: ExprKind::NamedCall {
                target: CallTarget::Builtin(Builtin::TestInvokeEntrypoint),
                args: vec![literal("run"), literal("{}")],
                evaluation_order: vec![1, 0],
            },
            ty: Type::Unit,
        };
        let appended = append_test_call_site(&context, &Expr::String("call".to_owned()), named)
            .expect("append call site");
        let ExprKind::NamedCall {
            args,
            evaluation_order,
            ..
        } = appended.kind()
        else {
            panic!("named calls stay named");
        };
        assert_eq!(args.len(), 3);
        assert_eq!(evaluation_order, &[1, 0, 2]);
        assert_eq!(
            decode_site(&args[2]),
            crate::testing::TestCallSite {
                source_id: 0,
                byte_start: 0,
                byte_end: 0,
            }
        );
        let positional = typed_builtin_call(
            Builtin::TestActorAccount,
            vec![literal("alice")],
            Type::AccountId,
        );
        let appended =
            append_test_call_site(&context, &Expr::String("call".to_owned()), positional)
                .expect("append call site");
        let ExprKind::Call { args, .. } = appended.kind() else {
            panic!("positional calls stay positional");
        };
        assert_eq!(args.len(), 2);
        let _ = decode_site(&args[1]);
    }
    #[test]
    fn assert_rejects_extra_args() {
        let program =
            parse("fn f() { test::assert(true, message: false); }").expect("parse assert");
        let err = SemanticContext::with_capabilities(false, true)
            .analyze(&program)
            .expect_err("assert message type should error");
        assert!(
            err.message
                .contains("`test::assert` expects `message` to be a string or int, found `bool`"),
            "{}",
            err.message
        );
    }
    #[test]
    fn in_memory_map_constructor_is_rejected() {
        let program = parse("fn f() { let StateMap<Name, int> m = StateMap::new(); let _x = m; }")
            .expect("parse StateMap::new");
        let err = analyze(&program).expect_err("V1 StateMap values must be durable state");
        assert!(
            err.message
                .contains("StateMap values may only refer directly to top-level durable state")
                || err.code == "E_STATE_MAP_ALIAS"
                || err
                    .message
                    .contains("unknown function or builtin `StateMap::new`"),
            "unexpected error: {}",
            err.message
        );
    }
    analyze_ok_tests! { bytes_equality_is_allowed: r#"fn f() { let bytes b = b"hi"; let bytes c = b"hi"; let _x = b == c; }"# => "parse bytes equality", "bytes equality should be allowed"; }
    #[test]
    fn bytes_literal_types_as_bytes() {
        let program = parse(r#"fn f() { let bytes b = b"ab"; }"#).expect("parse bytes literal");
        let typed = analyze(&program).expect("analyze bytes literal");
        let TypedItem::Function(f) = &typed.items[0];
        let stmt = f.body.statements.first().expect("statement present");
        match stmt {
            TypedStatement::Let { value, .. } => {
                assert!(matches!(value.expr, ExprKind::Bytes(_)));
                assert_eq!(value.ty, Type::Bytes);
            }
            other => panic!("expected let statement, got {other:?}"),
        }
    }
    #[test]
    fn state_map_key_type_is_validated() {
        let program = parse("state StateMap<Json, int> M; fn f() {}").expect("parse state map");
        let err = analyze(&program).expect_err("state map key should be validated");
        assert!(
            err.message
                .contains("StateMap key type `Json` is not supported"),
            "unexpected error: {}",
            err.message
        );
    }
    #[test]
    fn durable_state_map_key_domain_matches_generated_policy() {
        let supported = [
            Type::Int,
            Type::Decimal,
            Type::Quantity,
            Type::Bool,
            Type::String,
            Type::Bytes,
            Type::DataSpaceId,
            Type::AccountId,
            Type::AssetDefinitionId,
            Type::AssetId,
            Type::NftId,
            Type::DomainId,
            Type::Name,
        ];
        let expected_names = kotodama_surface::source_policy::V1_STATE_MAP_KEY_TYPE_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            supported.iter().map(type_name).collect::<Vec<_>>(),
            expected_names
        );
        assert!(supported.iter().all(is_supported_durable_key_type));
        for unsupported in [
            Type::Json,
            Type::AxtDescriptor,
            Type::AxtAnchoredSpendV1,
            Type::ProofBlob,
            Type::SoracloudRequest,
            Type::SoracloudResponse,
        ] {
            assert!(
                !is_supported_durable_key_type(&unsupported),
                "{} must not enter the durable key ABI",
                type_name(&unsupported)
            );
        }
    }
    analyze_reject_contains_tests! { immutable_field_assignment_is_rejected: "fn f() { let t = (1, 2); t.0 = 3; }" => "parse field assignment", err = "field assignment should error", "cannot assign to immutable binding"; }
    analyze_ok_tests! { info_accepts_int: "fn f() { debug::info(42); }" => "parse info", "info should accept int"; }
    #[test]
    fn view_entrypoints_accept_diagnostic_logging() {
        let program =
            parse("seiyaku Demo { view fn inspect() authorize(anyone) { debug::info(42); } }")
                .expect("parse debug logging in a view");
        analyze(&program).expect("debug::info is diagnostics-only and allowed in views");
    }
    #[test]
    fn vector_length_control_is_not_a_source_builtin() {
        let program = parse("fn f() { runtime::set_vector_length(8); }").expect("parse setvl");
        let error = analyze(&program).expect_err("vector metadata is compiler-owned");
        assert!(
            error
                .message
                .contains("unknown function or builtin `runtime::set_vector_length`"),
            "{error:?}"
        );
    }
    analyze_ok_tests! { trigger_event_accepts_no_args: "fn f() { let ev = context::trigger_event(); let _kind = ev.get_name(Name::parse(\"kind\")); }" => "parse trigger_event", "trigger_event should type-check"; }
    analyze_reject_contains_diagnostic_tests! { public_entrypoints_reject_trigger_event: "seiyaku Demo { permission InspectTrigger;  kotoage fn f() authorize(InspectTrigger) { let _ev = context::trigger_event(); } }" => "parse public trigger_event", err = "public trigger_event should fail", "cannot use `context::trigger_event` here", "unexpected error message: {}"; }
    analyze_ok_tests! { trigger_callbacks_accept_trigger_event_payload_helpers: include_str!( "semantic/test_sources/trigger_callbacks_accept_trigger_event_payload_helpers_1.ko" ) => "parse trigger callback trigger_event", "trigger callback trigger_event should type-check"; }
    #[test]
    fn namespaced_trigger_callbacks_are_rejected_before_semantic_analysis() {
        for source in [
            include_str!(
                "semantic/test_sources/namespaced_trigger_callback_does_not_require_local_entrypoint_1.ko"
            ),
            include_str!(
                "semantic/test_sources/namespaced_trigger_callback_does_not_mark_local_function_as_trigger_callback_1.ko"
            ),
        ] {
            let error = parse(source).expect_err("remote callback must not compile");
            assert!(error.contains("E_TRIGGER_TARGET_NAMESPACE"), "{error}");
        }
    }
    analyze_test_ok_tests! { invoke_entrypoint_accepts_test_functions: include_str!( "semantic/test_sources/invoke_entrypoint_accepts_test_functions_1.ko" ) => "parse invoke_entrypoint", "invoke_entrypoint in tests should type-check"; }
    analyze_test_reject_contains_tests! { invoke_entrypoint_rejects_non_test_functions: include_str!( "semantic/test_sources/invoke_entrypoint_rejects_non_test_functions_1.ko" ) => "parse non-test invoke_entrypoint", err = "non-test invoke_entrypoint should fail", "available only in #[test] functions"; }
    analyze_test_ok_tests! { invoke_entrypoint_accepts_name_literal_target: include_str!( "semantic/test_sources/invoke_entrypoint_accepts_name_literal_target_1.ko" ) => "parse name literal invoke_entrypoint", "name literal invoke_entrypoint should type-check"; }
    #[test]
    fn invoke_entrypoint_rejects_non_literal_target() {
        let program = parse(include_str!(
            "semantic/test_sources/invoke_entrypoint_rejects_non_literal_target_1.ko"
        ))
        .expect("parse dynamic target invoke_entrypoint");
        let err = analyze_test(&program).expect_err("dynamic target should fail");
        assert!(
            err.message
                .contains("requires a literal public or lifecycle target")
        );
    }
    analyze_test_reject_contains_tests! { invoke_entrypoint_requires_typed_argument_record: include_str!( "semantic/test_sources/invoke_entrypoint_rejects_non_json_payload_1.ko" ) => "parse non-record test arguments", err = "non-record arguments should fail", "require a typed record"; }
    #[test]
    fn invoke_entrypoint_rejects_internal_target() {
        let program = parse(include_str!(
            "semantic/test_sources/invoke_entrypoint_rejects_internal_target_1.ko"
        ))
        .expect("parse internal target invoke_entrypoint");
        let err = analyze_test(&program).expect_err("internal target should fail");
        assert!(
            err.message
                .contains("may only target kotoage/view/hajimari/kaizen")
        );
    }
    analyze_test_ok_tests! { invoke_entrypoint_as_and_actor_helpers_type_check_in_tests: include_str!( "semantic/test_sources/invoke_entrypoint_as_and_actor_helpers_type_check_in_tests_1.ko" ) => "parse invoke_entrypoint_as", "test helpers should type-check"; }
    analyze_test_ok_tests! { invoke_entrypoint_as_accepts_tuple_returning_targets: include_str!( "semantic/test_sources/invoke_entrypoint_as_accepts_tuple_returning_targets_1.ko" ) => "parse tuple invoke_entrypoint_as", "tuple-returning target should type-check"; }
    #[test]
    fn standalone_test_helpers_preserve_external_entrypoint_kind() {
        let target = parse(include_str!(
            "semantic/test_sources/standalone_test_helpers_preserve_external_entrypoint_kind_1.ko"
        ))
        .expect("parse target contract");
        let signatures = SemanticContext::with_capabilities(false, true)
            .resolve_function_signatures(&target)
            .expect("resolve target signatures");
        let accepted = parse(include_str!(
            "semantic/test_sources/standalone_test_helpers_preserve_external_entrypoint_kind_2.ko"
        ))
        .expect("parse standalone test module");
        SemanticContext::with_capabilities(false, true)
            .analyze_with_external_functions(&accepted, &signatures)
            .expect("external lifecycle entrypoint should retain its kind");
        let rejected = parse(include_str!("semantic/test_sources/invokes_lifecycle_1.ko"))
            .expect("parse private-helper test module");
        let error = SemanticContext::with_capabilities(false, true)
            .analyze_with_external_functions(&rejected, &signatures)
            .expect_err("private target helper must not become an entrypoint");
        assert_eq!(error.code(), "E_TEST_ENTRYPOINT_KIND");
        let direct_call = parse(include_str!(
            "semantic/test_sources/invokes_private_helper_1.ko"
        ))
        .expect("parse direct external-entrypoint call");
        let error = SemanticContext::with_capabilities(false, true)
            .analyze_with_external_functions(&direct_call, &signatures)
            .expect_err("external entrypoints must retain the contract-call boundary");
        assert_eq!(error.code(), "K2004");
    }
    analyze_test_reject_contains_tests! { actor_helpers_reject_non_test_functions: include_str!( "semantic/test_sources/actor_helpers_reject_non_test_functions_1.ko" ) => "parse non-test actor helper", err = "actor helper outside test should fail", "available only in #[test] functions"; }
    analyze_ok_tests! { view_entrypoints_accept_explicit_json_getter_on_typed_json_parameter: "seiyaku Demo { view fn f(Json ev) authorize(anyone) -> Option<int> { return ev.get_int(Name::parse(\"n\")); } }" => "parse view get_int", "typed Json parameters may use explicit JSON getters"; }
    analyze_reject_contains_diagnostic_tests! { view_entrypoints_reject_get_or_insert: "seiyaku Demo { state StateMap<int, int> balances; view fn f() authorize(anyone) -> int { return balances.get_or_insert(7, 9); } }" => "parse get_or_insert", err = "view get_or_insert should fail", "`view fn` functions cannot use the state-writing map helper `get_or_insert`", "unexpected error message: {}"; }
    analyze_ok_tests! { view_entrypoints_read_with_get_and_unwrap_or: "seiyaku Demo { state StateMap<int, int> balances; view fn f() authorize(anyone) -> int { return balances.get(7).unwrap_or(9); } }" => "parse get", "view get with unwrap_or should type-check"; }
    analyze_ok_tests! { views_may_log_with_debug_info: "seiyaku Demo { view fn f() authorize(anyone) -> int { debug::info(\"quote\"); helper() } fn helper() -> int { debug::info(1); 1 } }" => "parse debug info", "debug::info is diagnostics-only and allowed in views"; }
    #[test]
    fn state_map_get_returns_option_without_intercepting_user_get_function() {
        let program = parse(
            "seiyaku Demo { state StateMap<int, int> balances; fn get(int _ value) -> int { return value; } view fn lookup(int key) authorize(anyone) -> Option<int> { return balances.get(key); } view fn echo(int value) authorize(anyone) -> int { return get(value); } }",
        )
        .expect("parse canonical and user-defined get calls");
        let typed = analyze(&program).expect("both get call forms should resolve unambiguously");
        let returns = typed
            .items
            .iter()
            .map(|item| match item {
                TypedItem::Function(function) => (function.name.as_str(), function.ret_ty.clone()),
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(
            returns.get("lookup"),
            Some(&Some(Type::Option(Box::new(Type::Int))))
        );
        assert_eq!(returns.get("echo"), Some(&Some(Type::Int)));
    }
    #[test]
    fn state_map_reads_require_explicit_option_handling() {
        for (source, expected) in [
            (
                "seiyaku Demo { state StateMap<int, int> balances; view fn read() authorize(anyone) -> int { return balances[1]; } }",
                "E_STATE_MAP_OPTIONAL_READ",
            ),
            (
                "seiyaku Demo { permission Write;  state StateMap<int, int> balances; kotoage fn add() authorize(Write) { balances[1] += 1; } }",
                "E_STATE_MAP_OPTIONAL_READ",
            ),
            (
                "seiyaku Demo { state StateMap<int, int> balances; view fn read() authorize(anyone) -> Option<int> { return get(balances, 1); } }",
                "unknown function or builtin `get`",
            ),
        ] {
            let program =
                parse(source).expect("invalid StateMap read should parse before resolution");
            let error = analyze(&program).expect_err("invalid StateMap read must fail closed");
            if expected.starts_with("E_") {
                assert_eq!(
                    error.code, expected,
                    "unexpected diagnostic code for `{source}`: {error:?}"
                );
            } else {
                assert!(
                    error.message.contains(expected),
                    "unexpected error for `{source}`: {error:?}"
                );
            }
        }
        let write = parse(
            "seiyaku Demo { permission Write;  state StateMap<int, int> balances; kotoage fn set(int key, int value) authorize(Write) { balances[key] = value; } }",
        )
        .expect("parse indexed StateMap write");
        analyze(&write).expect("simple indexed StateMap assignment must remain valid");
    }
    #[test]
    fn state_map_remove_returns_option_for_scalar_values() {
        let program = parse(
            "seiyaku Demo { permission WriteState;  state StateMap<Name, int> balances; kotoage fn f(Name key) authorize(WriteState) -> Option<int> { return balances.remove(key); } }",
        )
        .expect("parse StateMap.remove");
        let typed = analyze(&program).expect("scalar StateMap.remove should type-check");
        let function = typed
            .items
            .iter()
            .map(|item| match item {
                TypedItem::Function(function) => function,
            })
            .find(|function| function.name == "f")
            .expect("kotoage function");
        let (reads, writes) = function_state_accesses(function, &typed.states);
        assert!(reads.contains("state:balances"));
        assert!(writes.contains("state:balances"));
    }
    analyze_reject_contains_diagnostic_tests! { view_entrypoints_reject_state_map_remove: "seiyaku Demo { state StateMap<int, int> balances; view fn f() authorize(anyone) -> Option<int> { return balances.remove(7); } }" => "parse StateMap.remove in view", err = "view remove must fail", "view function `f` cannot perform durable state mutation", "unexpected error message: {}"; }
    analyze_reject_contains_diagnostic_tests! { view_entrypoints_reject_direct_durable_state_assignment: "seiyaku Demo { state int counter; hajimari() { counter = 0; } view fn f() authorize(anyone) -> int { counter = 1; return counter; } }" => "parse direct durable state assignment", err = "view durable state assignment should fail", "view function `f` cannot perform durable state mutation", "unexpected error message: {}"; }
    analyze_reject_contains_diagnostic_tests! { view_entrypoints_reject_state_map_mutation: "seiyaku Demo { state StateMap<int, int> balances; view fn f() authorize(anyone) -> int { balances[7] = 9; return 1; } }" => "parse state map mutation", err = "view state map mutation should fail", "view function `f` cannot perform durable state mutation", "unexpected error message: {}"; }
    analyze_reject_contains_diagnostic_tests! { view_entrypoints_reject_transitive_durable_state_mutation: "seiyaku Demo { state int counter; hajimari() { counter = 0; } fn helper() { counter = counter + 1; } view fn f() authorize(anyone) -> int { helper(); return counter; } }" => "parse transitive durable state mutation", err = "view transitive durable mutation should fail", "view function `f` cannot call `helper` because `helper` performs durable state mutation", "unexpected error message: {}"; }
    #[test]
    fn compiler_internal_builtins_are_rejected_from_source() {
        for name in [
            "alloc",
            "domain",
            "blob",
            "norito_bytes",
            "soracloud_request",
            "soracloud_response",
            "grow_heap",
            "debug_print",
            "debug_log",
            "setvl",
            "keys_take2",
            "values_take2",
            "keys_values_take2",
            "get_merkle_path",
            "get_merkle_compact",
            "get_register_merkle_compact",
            "pointer_to_norito",
            "json_set_int_direct",
            "json_set_account_id_direct",
            "json_get_int_direct",
            "json_get_numeric_direct",
            "json_get_json_direct",
            "json_get_name_direct",
            "json_get_account_id_direct",
            "json_get_asset_definition_id_direct",
            "json_get_nft_id_direct",
            "json_get_blob_hex_direct",
            "build_path_key_norito_direct",
            "schema_encode_direct",
            "schema_decode_direct",
            "schema_info_direct",
            "numeric_to_int_direct",
            "numeric_add_direct",
            "numeric_sub_direct",
            "numeric_mul_direct",
            "numeric_div_direct",
            "numeric_rem_direct",
            "numeric_neg_direct",
            "numeric_eq_direct",
            "numeric_ne_direct",
            "numeric_lt_direct",
            "numeric_le_direct",
            "numeric_gt_direct",
            "numeric_ge_direct",
        ] {
            let program = parse(&format!("fn f() {{ {name}(); }}"))
                .expect("compiler-internal builtin name should parse as a call");
            let err = analyze(&program).expect_err("internal builtin must be source-inaccessible");
            assert!(
                err.message.contains("compiler-internal")
                    || err.message.contains("unknown function or builtin"),
                "unexpected error for {name}: {}",
                err.message
            );
        }
    }
    #[test]
    fn generic_execute_instruction_is_not_a_builtin() {
        let program = parse("fn f(bytes payload) { execute_instruction(payload); }")
            .expect("unknown call should parse before semantic resolution");
        let err = analyze(&program).expect_err("generic instruction execution must be unknown");
        assert_eq!(
            err.message,
            "unknown function or builtin `execute_instruction`"
        );
    }
    #[test]
    fn raw_namespaced_host_bridges_are_not_builtins() {
        for source_name in [
            "contract::call",
            "seiyaku::call",
            "runtime::set_vector_length",
            "debug::print_i64",
            "debug::log",
            "axt::verify_proof",
            "soracloud::read_committed_state",
            "soracloud::read_secret",
        ] {
            let Ok(program) = parse(&format!("fn f() {{ {source_name}(); }}")) else {
                assert!(matches!(source_name, "contract::call" | "seiyaku::call"));
                continue;
            };
            let error = analyze(&program).expect_err("raw host bridge must fail closed");
            assert!(
                error.message.contains("unknown function or builtin"),
                "unexpected error for {source_name}: {error:?}"
            );
        }
    }
    #[test]
    fn noncanonical_crypto_aliases_are_rejected() {
        for alias in ["sm::hash", "sm::verify", "sm::seal_gcm", "sm::open_ccm"] {
            let args = match alias {
                "sm::hash" => "b\"x\"",
                "sm::verify" => "b\"m\", b\"s\", b\"k\"",
                _ => "b\"k\", b\"n\", b\"a\", b\"m\"",
            };
            let program = parse(&format!("fn f() {{ let _x = {alias}({args}); }}"))
                .expect("noncanonical alias parses before semantic resolution");
            let error = analyze(&program).expect_err("alias must not bypass canonical resolution");
            assert_eq!(
                error.message,
                format!("unknown function or builtin `{alias}`")
            );
        }
    }
    #[test]
    fn truncated_scalar_crypto_and_ephemeral_nullifier_calls_are_rejected_from_source() {
        for (name, args) in [
            ("crypto::poseidon2", "left: 1, right: 2"),
            ("crypto::poseidon6", "a: 1, b: 2, c: 3, d: 4, e: 5, f: 6"),
            ("crypto::pubkgen", "1"),
            ("crypto::use_nullifier", "1"),
        ] {
            let program = parse(&format!("fn f() {{ let _value = {name}({args}); }}"))
                .expect("retired scalar crypto spelling parses before resolution");
            let error = analyze(&program).expect_err("retired source capability must fail closed");
            assert_eq!(error.code, "K2002", "{name}: {error:?}");
            assert_eq!(
                error.message,
                format!("unknown function or builtin `{name}`")
            );
        }
    }
    #[test]
    fn branded_feature_diagnostics_never_leak_compiler_internal_english_names() {
        for (source, branded, internal) in [
            (
                "fn f() { ledger::query::seiyaku_manifest(true); }",
                "ledger::query::seiyaku_manifest",
                "query_get_contract_manifest",
            ),
            (
                "fn f() { ledger::query::seiyaku_instance(true); }",
                "ledger::query::seiyaku_instance",
                "query_get_contract_instance",
            ),
            (
                "fn f() { ledger::seiyaku::grant_permission(1); }",
                "ledger::seiyaku::grant_permission",
                "grant_contract_permission",
            ),
            (
                "fn f() { ledger::seiyaku::revoke_permission(1); }",
                "ledger::seiyaku::revoke_permission",
                "revoke_contract_permission",
            ),
            (
                "fn f() { context::seiyaku_subject(1); }",
                "context::seiyaku_subject",
                "contract_subject",
            ),
            (
                "fn f() { context::seiyaku_address(1); }",
                "context::seiyaku_address",
                "contract_address",
            ),
            (
                "fn f() { context::kotoage(1); }",
                "context::kotoage",
                "entrypoint",
            ),
        ] {
            let program = parse(source).expect("parse branded diagnostic fixture");
            let error = analyze(&program).expect_err("wrong branded call must fail");
            assert!(
                error.message.contains(branded),
                "missing branded spelling `{branded}`: {error:?}"
            );
            assert!(
                !error.message.contains(internal),
                "diagnostic leaked internal spelling `{internal}`: {error:?}"
            );
        }
        for (source, branded, internal) in [
            (
                "seiyaku T { #[test] fn f() { test::invoke_kotoage(1); } }",
                "test::invoke_kotoage",
                "invoke_entrypoint",
            ),
            (
                "seiyaku T { #[test] fn f() { test::invoke_kotoage_as(1); } }",
                "test::invoke_kotoage_as",
                "invoke_entrypoint_as",
            ),
        ] {
            let program = parse(source).expect("parse branded test-helper fixture");
            let error = analyze_test(&program).expect_err("wrong branded test call must fail");
            assert!(error.message.contains(branded), "{error:?}");
            assert!(!error.message.contains(internal), "{error:?}");
        }
    }
    #[test]
    fn language_feature_diagnostics_use_only_branded_terms() {
        fn assert_branded(message: &str) {
            let forbidden = ["contract", "entrypoint", "initialization", "upgrade"];
            for word in message
                .split(|character: char| !character.is_alphanumeric() && character != '_')
                .filter(|word| !word.is_empty())
            {
                assert!(
                    !forbidden.contains(&word.to_ascii_lowercase().as_str()),
                    "diagnostic leaked English language-feature alias `{word}`: {message}"
                );
            }
        }
        for source in [
            "module M { kotoage fn run() authorize(anyone) {} }",
            "module M { view fn read() authorize(anyone) {} }",
            "seiyaku S { fn helper() authorize(Run) {} }",
        ] {
            let message = crate::parser::parse(source)
                .expect_err("invalid declaration must produce a parser diagnostic");
            assert_branded(&message);
        }
        for source in [
            "seiyaku S { trigger wake -> missing { on time pre_commit; } }",
            "seiyaku S { view fn read() authorize(anyone) {} trigger wake -> read { on time pre_commit; } }",
            "seiyaku S { fn helper() {} trigger wake -> helper { on time pre_commit; } }",
            "seiyaku S { state StateMap<int, int> values; view fn read() authorize(anyone) -> int { return values.ensure(1, 2); } }",
            "seiyaku S { permission Admin; permission Run;  kotoage fn admin() authorize(Admin) {} kotoage fn run() authorize(Run) { admin(); } }",
            "seiyaku S { state int first; state int second; hajimari() { first = 0; } }",
        ] {
            let program = parse(source).expect("semantic diagnostic fixture must parse");
            let error =
                analyze(&program).expect_err("invalid program must produce a semantic diagnostic");
            assert_branded(&error.message);
        }
    }
    #[test]
    fn public_valcom_operands_are_rejected_in_favour_of_typed_secrets() {
        let program = parse("fn f() -> int { return crypto::valcom(left: 7, right: 11); }")
            .expect("parse public valcom call");
        let error = SemanticContext::with_zk_enabled(true)
            .analyze(&program)
            .expect_err("public scalar commitment must fail closed");
        assert_eq!(error.code, "K2003");
        assert_eq!(
            error.message,
            "crypto::valcom expects two typed Secret<int|decimal|quantity> arguments"
        );
    }
    #[test]
    fn valcom_registry_rejects_non_zk_analysis_with_the_source_name() {
        let result = analyze_surface_builtin_call(
            &SemanticContext::new(),
            Builtin::Valcom,
            Vec::new(),
            Some(&Type::Int),
        );
        let error = canonicalize_builtin_result(Builtin::Valcom, result)
            .expect_err("the Secret-only commitment requires ZK mode");
        assert_eq!(error.code, "E_ZK_MODE_REQUIRED");
        assert_eq!(
            error.message,
            "builtin `crypto::valcom` requires ZK mode in compiler build configuration"
        );
    }
    #[test]
    fn public_entrypoints_reject_zk_verify_without_permission() {
        let mut program = parse(
            "seiyaku Demo { permission Verify;  kotoage fn verify(bytes payload) authorize(Verify) { crypto::zk::verify_batch(request: payload); } }",
        )
        .expect("parse public zk verify");
        let function = program
            .items
            .iter_mut()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "verify" => Some(function),
                _ => None,
            })
            .expect("verify function");
        function.modifiers.authorization = None;
        let err = SemanticContext::with_zk_enabled(true)
            .analyze(&program)
            .expect_err("a fabricated public zk verifier AST should require permission");
        assert!(
            err.message
                .contains("public function `verify` requires an explicit `authorize(...)` policy"),
            "unexpected error message: {}",
            err.message
        );
    }
    #[test]
    fn runtime_entrypoints_cannot_be_direct_call_targets() {
        for (target_declaration, target_name) in [
            (
                "permission Admin; kotoage fn admin() authorize(Admin) {}",
                "admin",
            ),
            ("view fn inspect() authorize(anyone) {}", "inspect"),
        ] {
            let source = format!(
                "seiyaku Demo {{ permission Run;  {target_declaration} kotoage fn run() authorize(Run) {{ {target_name}(); }} }}"
            );
            let error = analyze_error(&source);
            assert!(
                error.message.contains(&format!(
                    "seiyaku runtime function `{target_name}` cannot be called directly"
                )),
                "unexpected direct-entrypoint diagnostic: {error:?}"
            );
        }
    }
    #[test]
    fn privileged_effect_table_covers_release_mutators() {
        for name in [
            "transfer_asset",
            "register_asset",
            "create_nfts_for_all_users",
            "transfer_batch",
            "axt_begin",
            "axt_touch",
            "axt_stage_anchored_spend",
            "axt_commit",
        ] {
            let builtin = Builtin::from_name(name).expect("registered builtin");
            assert!(
                builtin.spec().effects.host_side_effects,
                "privileged builtin `{name}` must be classified as effectful"
            );
        }
    }
    analyze_ok_tests! { canonical_context_and_ledger_namespaces_type_check: include_str!( "semantic/test_sources/canonical_context_and_ledger_namespaces_type_check_1.ko" ) => "parse canonical namespaced calls", "canonical context and ledger namespaces should type-check"; }
    #[test]
    fn escrow_open_offer_signature_matches_the_host_abi() {
        let program = parse(include_str!(
            "semantic/test_sources/escrow_open_offer_signature_matches_the_host_abi_1.ko"
        ))
        .expect("parse canonical escrow calls");
        analyze(&program).expect("three required arguments plus optional evidence must type-check");
        let invalid = parse(include_str!(
            "semantic/test_sources/escrow_open_offer_signature_matches_the_host_abi_2.ko"
        ))
        .expect("parse invalid escrow call");
        let error = analyze(&invalid).expect_err("the retired five-argument shape must fail");
        assert_eq!(error.code, "K2003");
        assert!(
            error.message.contains("expects at most 4 arguments, got 5"),
            "unexpected diagnostic: {}",
            error.message
        );
    }
    #[test]
    fn public_entrypoints_reject_state_mutation_without_permission() {
        let mut program = parse(
            "seiyaku Demo { permission Set;  state int counter; hajimari() { counter = 0; } kotoage fn set() authorize(Set) { counter = 1; } }",
        )
        .expect("parse public state mutation");
        let function = program
            .items
            .iter_mut()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "set" => Some(function),
                _ => None,
            })
            .expect("set function");
        function.modifiers.authorization = None;
        let err = analyze(&program)
            .expect_err("a fabricated public state-mutation AST should require permission");
        assert!(
            err.message
                .contains("public function `set` requires an explicit `authorize(...)` policy"),
            "unexpected error message: {}",
            err.message
        );
    }
    #[test]
    fn recursive_functions_are_rejected() {
        for source in [
            "fn recurse() { recurse(); }",
            "fn first() { second(); } fn second() { first(); }",
        ] {
            let program = parse(source).expect("parse recursive functions");
            let err = analyze(&program).expect_err("function recursion must be rejected");
            assert!(
                err.message
                    .contains("recursive function calls are not supported in Kotodama V1"),
                "unexpected error: {}",
                err.message
            );
        }
    }
    #[test]
    fn view_entrypoints_reject_transitive_zk_verify() {
        let program = parse(
            "seiyaku Demo { fn helper(bytes payload) { crypto::zk::verify_batch(request: payload); } view fn f(bytes payload) authorize(anyone) -> int { helper(payload: payload); return 1; } }",
        )
        .expect("parse transitive zk verify");
        let err = SemanticContext::with_zk_enabled(true)
            .analyze(&program)
            .expect_err("view zk verify should fail");
        assert!(
            err.message.contains(
                "view function `f` cannot call `helper` because `helper` performs host side effects"
            ),
            "unexpected error message: {}",
            err.message
        );
    }
    analyze_ok_tests! { resolve_account_alias_accepts_canonical_string: "fn f() { let _acct = ledger::account::resolve_alias(alias: \"banking@centralbank\"); }" => "parse resolve_account_alias", "resolve_account_alias should type-check"; }
    analyze_ok_tests! { resolve_account_alias_accepts_alias_bytes: r#"fn f() { let alias = b"banking@centralbank"; let _acct = ledger::account::resolve_alias(alias: alias); }"# => "parse resolve_account_alias blob", "resolve_account_alias blob should type-check"; }
    analyze_ok_tests! { durable_state_maps_accept_forward_declared_struct_values: include_str!( "semantic/test_sources/durable_state_maps_accept_forward_declared_struct_values_1.ko" ) => "parse durable struct map", "durable struct-valued state map should type-check"; }
    #[rustfmt::skip]
    analyze_ok_tests! { equality_between_event_account_and_resolved_alias_type_checks: "fn f() { \
                let ev = context::trigger_event(); \
                if let Option::some(dst) = ev.get_account_id(Name::parse(\"account_id\")) { \
                    let sink = ledger::account::resolve_alias(alias: \"banking@centralbank\"); \
                    let _same = dst == sink; \
                } \
            }" => "parse account equality", "account-id equality should type-check"; }
    analyze_ok_tests! { get_asset_definition_id_accepts_trigger_payloads: "fn f() { let ev = context::trigger_event(); let _asset = ev.get_asset_definition_id(Name::parse(\"asset_definition_id\")); }" => "parse get_asset_definition_id", "get_asset_definition_id should type-check"; }
    analyze_ok_tests! { get_quantity_returns_an_optional_trigger_quantity: "fn f() { let ev = context::trigger_event(); let Option<quantity> value = ev.get_quantity(Name::parse(\"amount\")); }" => "parse get_quantity", "get_quantity should type-check as Option<quantity>"; }
    analyze_ok_tests! { durable_string_state_is_supported: include_str!( "semantic/test_sources/durable_string_state_is_supported_1.ko" ) => "parse string state", "string state should be supported"; }
    analyze_ok_tests! { durable_struct_string_field_is_supported: include_str!( "semantic/test_sources/durable_struct_string_field_is_supported_1.ko" ) => "parse state struct", "string state field should be supported"; }
    #[test]
    fn nested_state_map_is_rejected() {
        let ty = Type::Struct {
            name: "S".into(),
            fields: Arc::from(vec![(
                "children".into(),
                Type::StateMap(Box::new(Type::Int), Box::new(Type::Int)),
            )]),
        };
        let err = validate_state_type(&ty).expect_err("nested StateMap must be rejected");
        assert!(
            err.message.contains("nested StateMap is not supported"),
            "unexpected error: {}",
            err.message
        );
    }
    analyze_ok_tests! { durable_option_and_result_accept_aggregate_payloads: include_str!( "semantic/test_sources/durable_option_and_result_accept_aggregate_payloads_1.ko" ) => "parse aggregate sum state", "aggregate Option/Result state should type-check"; }
    analyze_ok_tests! { local_sum_annotations_resolve_aggregate_payloads_contextually: include_str!("semantic/test_sources/local_sum_annotations_resolve_aggregate_payloads_contextually_1.ko") => "parse aggregate local sums", "aggregate local sum annotations should resolve nominal payloads"; }
    #[test]
    fn explicit_numeric_conversions_preserve_nominal_types() {
        let program = parse(
            "seiyaku C { fn f(int value) -> decimal { \
                return decimal::from_int(value); \
            } }",
        )
        .expect("parse explicit conversions");
        let typed = analyze(&program).expect("analyze explicit conversions");
        let TypedItem::Function(f) = &typed.items[0];
        assert_eq!(f.ret_ty, Some(Type::Decimal));
    }
    #[rustfmt::skip]
    analyze_reject_contains_tests! { quantity_remains_nominal_in_mixed_numeric_operations: "seiyaku C { fn f(quantity a, int b) { \
                let _x = a + b; \
            } }" => "parse nominal numeric types", err = "mixed numeric types should error", "operator `+` is not defined for `quantity` and `int`"; }
    #[test]
    fn exact_literals_infer_decimal_without_runtime_conversion() {
        let constant = returned_expr("fn value() -> decimal { return 2 + 0.5; }");
        assert_eq!(constant.ty, Type::Decimal);
        assert!(matches!(
            constant.kind(),
            ExprKind::DecimalLiteral { value, .. } if value.to_string() == "2.5"
        ));
        let arithmetic =
            returned_expr("fn value(decimal fraction) -> decimal { return 2 + fraction; }");
        assert!(matches!(
            arithmetic.kind(),
            ExprKind::Binary { left, right, .. }
                if matches!(left.kind(), ExprKind::DecimalLiteral { .. })
                    && matches!(right.kind(), ExprKind::Ident(_))
        ));
        analyze(
            &parse("fn value(decimal fraction) { let inferred = 2 + fraction; }")
                .expect("parse sibling-inferred decimal literal"),
        )
        .expect("a decimal sibling must infer an exact literal without a return context");
        let comparison =
            returned_expr("fn less(decimal fraction) -> bool { return 2 < fraction; }");
        assert!(matches!(
            comparison.kind(),
            ExprKind::Binary { left, right, .. }
                if matches!(left.kind(), ExprKind::DecimalLiteral { .. })
                    && matches!(right.kind(), ExprKind::Ident(_))
        ));
    }
    #[test]
    fn mixed_runtime_int_decimal_operations_require_explicit_conversion() {
        for source in [
            "fn value(int whole, decimal fraction) -> decimal { return whole + fraction; }",
            "fn less(int whole, decimal fraction) -> bool { return whole < fraction; }",
            "fn equal(int whole, decimal fraction) -> bool { return whole == fraction; }",
            "fn literal(int whole) -> decimal { return whole + 0.5; }",
        ] {
            let error = analyze_error(source);
            assert_eq!(error.code, "E_IMPLICIT_NUMERIC_CONVERSION");
            assert_eq!(
                error.message,
                "`int` and `decimal` operands cannot be mixed implicitly; convert the `int` with `decimal::from_int(value)` before arithmetic or comparison"
            );
        }
        analyze(
            &parse(
                "fn value(int whole, decimal fraction) -> decimal { \
                    return decimal::from_int(whole) + fraction; \
                }",
            )
            .expect("parse explicit conversion"),
        )
        .expect("an explicit int-to-decimal conversion must remain valid");
    }
    #[test]
    fn decimal_compound_assignment_requires_explicit_runtime_conversion() {
        let implicit = analyze_error(
            "fn accumulate(int delta) -> decimal { \
                var decimal value = 1.5; \
                value += delta; \
                return value; \
            }",
        );
        assert_eq!(implicit.code, "E_IMPLICIT_NUMERIC_CONVERSION");
        assert!(implicit.message.contains("decimal::from_int(value)"));
        let source = parse(
            "fn accumulate(int delta) -> decimal { \
                var decimal value = 1.5; \
                value += decimal::from_int(delta); \
                value += 2; \
                return value; \
            }",
        )
        .expect("parse explicit compound assignment conversion");
        let typed = analyze(&source).expect("explicit and contextual literal conversion must pass");
        let TypedItem::Function(function) = &typed.items[0];
        let assignments = function
            .body
            .statements
            .iter()
            .filter_map(|statement| match statement {
                TypedStatement::Let { name, value } if name == "value" => {
                    matches!(value.kind(), ExprKind::Binary { .. }).then_some(value)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(assignments.len(), 2);
        assert!(matches!(
            assignments[0].kind(),
            ExprKind::Binary { right, .. }
                if matches!(right.kind(), ExprKind::NumericCast { .. })
        ));
        assert!(matches!(
            assignments[1].kind(),
            ExprKind::Binary { right, .. }
                if matches!(right.kind(), ExprKind::DecimalLiteral { .. })
        ));
    }
    #[test]
    fn quantity_rejects_remainder_and_negation_surfaces() {
        let remainder = parse("seiyaku C { fn f(quantity a, quantity b) { let _x = a % b; } }")
            .expect("parse quantity remainder");
        let error = analyze(&remainder).expect_err("quantity remainder must fail");
        assert_eq!(error.code, "E_QUANTITY_REMAINDER");
        let negation = parse("seiyaku C { fn f(quantity a) { let _x = -a; } }")
            .expect("parse numeric negation");
        let error = analyze(&negation).expect_err("quantity negation must fail");
        assert_eq!(error.code, "E_QUANTITY_NEGATION");
    }
    analyze_ok_tests! { unsuffixed_whole_literal_is_contextual_in_a_quantity_position: "seiyaku C { fn f() -> quantity { return 1; } }" => "parse unsuffixed literal", "whole literal must coerce exactly in a quantity context"; }
    #[test]
    fn values_wider_than_u128_are_accepted_as_int() {
        let program = parse(
            "seiyaku C { fn wide_value() -> int { \
                return 340282366920938463463374607431768211456; \
            } }",
        )
        .expect("parse adaptive-width int");
        let typed = analyze(&program).expect("analyze adaptive-width int");
        let TypedItem::Function(function) = &typed.items[0];
        assert_eq!(function.ret_ty, Some(Type::Int));
    }
    analyze_ok_tests! { adaptive_int_values_use_width_independent_operators: "seiyaku C { fn f(int value) -> int { return value < 0 ? -value : value; } }" => "parse width-independent int expression", "ordinary int operators must accept the complete V1 domain"; }
    #[rustfmt::skip]
    analyze_ok_tests! { ledger_quantity_parameters_contextually_accept_whole_literals: "seiyaku C { fn f(AccountId account, AssetDefinitionId asset) { \
                ledger::asset::mint(account: account, asset_definition: asset, amount: 1); \
            } }" => "parse ledger amount call", "whole literal must coerce exactly at a quantity boundary"; }
    #[rustfmt::skip]
    analyze_ok_tests! { canonical_trigger_operations_type_check: "fn f() { \
                ledger::trigger::register(trigger_spec: Json::parse(\"{}\")); \
                ledger::trigger::unregister(trigger: Name::parse(\"wake\")); \
            }" => "parse canonical trigger operations", "analyze canonical trigger operations"; }
    include!("semantic/tests/trigger_semantics_tests.rs");
    #[test]
    fn typed_asset_definition_scale_drives_dynamic_quantity_rounding() {
        let program = parse(
            r#"seiyaku Precision {
            view fn round(AssetDefinitionId asset, quantity amount) authorize(anyone) -> quantity {
                return match ledger::query::asset_definition(asset) {
                    Option::some(value) => amount.div_round(divisor: 1.0,
                        scale: value.numeric_scale.unwrap_or(28), mode: Rounding::floor),
                    Option::none => 0,
                };
            }
        }"#,
        )
        .expect("parse authoritative precision read");
        analyze(&program).expect("query Option<int> must drive numeric rounding");
    }
    #[test]
    fn typed_core_queries_expose_declared_projection_and_page_types() {
        let program = parse(
            include_str!("semantic/test_sources/typed_core_queries_expose_declared_projection_and_page_types_1.ko"),
        )
        .expect("parse typed core queries");
        let typed = analyze(&program).expect("typed core query surface should type-check");
        let functions = typed
            .items
            .iter()
            .map(|item| match item {
                TypedItem::Function(function) => function,
            })
            .collect::<Vec<_>>();
        let account = functions
            .iter()
            .find(|function| function.name == "account")
            .expect("singular query helper");
        assert!(matches!(
            account.ret_ty,
            Some(Type::Option(ref view))
                if matches!(view.as_ref(), Type::Struct { name, .. } if name == "kotodama::AccountView")
        ));
        let accounts = functions
            .iter()
            .find(|function| function.name == "accounts")
            .expect("plural query helper");
        let Some(Type::Struct { name, fields }) = &accounts.ret_ty else {
            panic!("plural query must return QueryPage<AccountView>")
        };
        assert_eq!(name, QUERY_PAGE_NOMINAL_NAME);
        assert_eq!(
            render_type_name(accounts.ret_ty.as_ref().unwrap()),
            "QueryPage<AccountView>"
        );
        assert!(matches!(
            fields.as_ref(),
            [(items, Type::List(view, 64)), (next, Type::Option(offset))]
                if items == "items"
                    && next == "next_offset"
                    && matches!(view.as_ref(), Type::Struct { name, .. } if name == "kotodama::AccountView")
                    && offset.as_ref() == &Type::Int
        ));
    }
    #[test]
    fn typed_core_query_pages_require_names_and_bounded_constants() {
        let positional = analyze(
            &parse("fn f() { let _page = ledger::query::accounts(0, 64); }")
                .expect("parse positional page call"),
        )
        .expect_err("pagination calls are named-only");
        assert_eq!(positional.code, "E_NAMED_ARGUMENTS_REQUIRED");
        for (source, code) in [
            (
                "fn f() { let _page = ledger::query::accounts(offset: -1, limit: 64); }",
                "E_QUERY_OFFSET",
            ),
            (
                "fn f() { let _page = ledger::query::accounts(offset: 0, limit: -1); }",
                "E_QUERY_LIMIT",
            ),
            (
                "fn f() { let _page = ledger::query::accounts(offset: 0, limit: 0); }",
                "E_QUERY_LIMIT",
            ),
            (
                "fn f() { let _page = ledger::query::accounts(offset: 0, limit: 65); }",
                "E_QUERY_LIMIT",
            ),
            (
                "fn f() { let _page = ledger::query::accounts(offset: 18446744073709551616, limit: 64); }",
                "E_QUERY_OFFSET",
            ),
            (
                "fn f() { let _page = ledger::query::accounts(offset: 9223372036854775808, limit: 1); }",
                "E_QUERY_OFFSET",
            ),
            (
                "fn f() { let _page = ledger::query::accounts(offset: 9223372036854775807, limit: 1); }",
                "E_QUERY_OFFSET",
            ),
            (
                "fn f() { let _page = ledger::query::accounts(offset: 0, limit: 18446744073709551616); }",
                "E_QUERY_LIMIT",
            ),
        ] {
            let error = analyze(&parse(source).expect("parse invalid page bound"))
                .expect_err("invalid literal page bounds must fail during compilation");
            assert_eq!(error.code, code, "{source}: {}", error.message);
        }
        analyze(
            &parse(
                "fn f() { let _page = ledger::query::accounts(offset: 9223372036854775806, limit: 1); }",
            )
            .expect("parse maximum valid page window"),
        )
        .expect("an offset-plus-limit window ending at i64::MAX is valid");
    }
    analyze_reject_code_tests! { typed_core_singular_queries_reject_raw_bytes: "fn account(bytes raw) { let _view = ledger::query::account(raw); }" => "parse raw-byte core query", error = "core queries require their declared typed ID", "E_QUERY_KEY_TYPE"; }
    analyze_ok_tests! { tail_sums_matches_if_let_and_propagation_type_check_together: include_str!("semantic/test_sources/tail_sums_matches_if_let_and_propagation_type_check_together_1.ko") => "parse active-only sum program", "active-only sums and expression control flow must type-check"; }
    analyze_ok_tests! { divergent_expression_arms_inhabit_the_sibling_value_type: include_str!( "semantic/test_sources/divergent_expression_arms_inhabit_the_sibling_value_type_1.ko" ) => "parse divergent expression arms", "a returning arm must not synthesize a unit placeholder value"; }
    analyze_reject_code_tests! { discarded_branch_tail_does_not_count_as_function_return_coverage: include_str!("semantic/test_sources/discarded_branch_tail_does_not_count_as_function_return_coverage_1.ko") => "parse non-final mixed control flow", error = "a discarded branch value cannot satisfy a declared return type", "E_MISSING_RETURN"; }
    analyze_reject_code_tests! { wholly_divergent_expression_without_a_type_context_fails_closed: include_str!("semantic/test_sources/wholly_divergent_expression_without_a_type_context_fails_closed_1.ko") => "parse context-free divergent expression", error = "bottom-like expressions require a concrete context", "E_DIVERGING_EXPRESSION_CONTEXT"; }
    include!("semantic_sum_tests.rs");
    include!("semantic/tests/call_labels_and_patterns.rs");
    include!("semantic/tests/call_identity.rs");
}

#[cfg(test)]
mod event_tests;
