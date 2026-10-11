//! Compiler for the KOTODAMA language.
//!
//! This module implements a practical, growing compiler from Kotodama source into IVM bytecode
//! (`.to`). It performs parsing, a lightweight semantic pass, IR lowering, simple register
//! allocation, and final code generation with an IVM metadata header. ABI v1, vector metadata, and
//! bounded-iteration policy are compiler-owned; callers may select only deployment policy such as
//! ZK mode, cycle ceilings, safety profile, and production/test mode.
//!
//! Kotodama targets the IVM bytecode format exclusively. All helpers in this
//! module emit the canonical wide encoding introduced for the first release; no
//! alternate instruction layouts are generated.
mod access_hint_normalization;
#[cfg(test)]
mod compact_call_schema;
mod compact_emission;
#[cfg(test)]
mod emission_profile;
mod entrypoint_descriptors;
mod frame_emission;
mod local_emission;
#[cfg(test)]
mod local_structural_controls;
#[cfg(test)]
mod numeric_operands;
mod numeric_zero;
#[cfg(test)]
mod single_use_fixtures;
#[cfg(test)]
mod single_use_private;
#[cfg(test)]
mod state_operands;
mod statement_sources;
use access_hint_normalization::canonical_state_hint_keys;
use entrypoint_descriptors::build_entrypoint_descriptors;

/// Opaque phase boundaries used by the compiler regression benchmark.
#[doc(hidden)]
pub mod benchmark;
use super::{
    ast::{BinaryOp, FunctionKind, FunctionModifiers, SourceLocation, SourceUnitKind, UnaryOp},
    diagnostic::{Diagnostic, DiagnosticBundle, DiagnosticPhase, SourcePosition, SourceSpan},
    i18n::{self, Language, Message},
    ir::{self, Instr, Terminator},
    policy, regalloc,
    semantic::{self, TypedItem, TypedProgram},
};
use crate::{
    encoding, instruction,
    metadata::{
        self, CONTRACT_FEATURE_BIT_VECTOR, CONTRACT_FEATURE_BIT_ZK, EmbeddedContractInterfaceV1,
        EmbeddedEntrypointDescriptor, EmbeddedFunctionBudgetReportV1, EmbeddedSourceLocation,
        EmbeddedSourceMapEntryV1, EmbeddedStateDescriptor, EmbeddedStateFieldDescriptor,
        EmbeddedStateType, LITERAL_SECTION_MAGIC, LiteralKindV1, ProgramMetadata,
        encode_literal_descriptor,
    },
    pointer_abi::PointerType,
    syscalls,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use indexmap::IndexSet;
use iroha_crypto as _; // for Hash types in new APIs
use iroha_data_model::{
    Identifiable,
    account::AccountId,
    asset::{
        AssetBalanceScope,
        id::{AssetDefinitionId, AssetId},
    },
    escrow::EscrowId,
    isi::{
        BurnBox, ExecuteTrigger, GrantBox, InstructionBox, Log, MintBox, RegisterBox,
        RemoveKeyValueBox, RevokeBox, SetKeyValueBox, TransferBox, UnregisterBox,
    },
    nft::NftId,
    query::{QueryRequest, SingularQueryBox},
    role::RoleId,
    smart_contract::manifest::{
        AccessSetHints, DynamicAccessHint, EntryPointKind, EntrypointParamDescriptor,
        StateDescriptor, TriggerCallback, TriggerDescriptor,
    },
    trigger::{Trigger, TriggerId},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::{name::Name, state_path::StatePath};
use kotodama_surface::builtins::{Builtin, BuiltinAccess};
use norito::json;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
};
const WIDE_IMM_MIN: i32 = -128;
const WIDE_IMM_MAX: i32 = 127;
const LITERAL_SHIFT_REG: u8 = 26;
/// Default hash-covered execution ceiling emitted for a Kotodama V1 artifact.
pub const DEFAULT_MAX_CYCLES: u64 = 1_000_000;
const KOTODAMA_ABI_VERSION: u8 = 1;
const COLLECTION_ITERATION_CAP: u8 = 64;
const _: () = assert!(semantic::COLLECTION_ITERATION_LIMIT == COLLECTION_ITERATION_CAP as i64);
const _: () = assert!(
    kotodama_surface::source_policy::V1_DYNAMIC_ACCESS_MAX_KEYS == COLLECTION_ITERATION_CAP as u32
);
const _: () = assert!(
    ivm_abi::access_hints::DYNAMIC_ACCESS_HINT_MAX_KEYS_V1 == COLLECTION_ITERATION_CAP as u32
);
const GLOBAL_WILDCARD_KEY: &str = "*";
const STATE_WILDCARD_KEY: &str = "state:*";
const HINT_SKIP_DYNAMIC_STATE_PATH: &str = "dynamic state path is not compiler-resolved";
const HINT_SKIP_CONTRACT_CALL_TARGET: &str = "contract call target is not compiler-resolved";
const HINT_SKIP_INTERNAL_CALL_TARGET: &str = "internal call target is not compiler-resolved";
const HINT_SKIP_OPAQUE_ISI: &str = "opaque ISI access is not compiler-resolved";
const HINT_SKIP_DYNAMIC_INSTRUCTION_BRIDGE: &str =
    "instruction bridge requires conservative dynamic access";
fn multiply_defined_temps(program: &ir::Program) -> HashSet<(usize, ir::Temp)> {
    let mut seen = HashSet::new();
    let mut multiple = HashSet::new();
    for (function_index, function) in program.functions.iter().enumerate() {
        for block in &function.blocks {
            for instruction in &block.instrs {
                regalloc::visit_instr_defs(instruction, |destination| {
                    let key = (function_index, destination);
                    if !seen.insert(key) {
                        multiple.insert(key);
                    }
                });
            }
        }
    }
    multiple
}
const HINT_SKIP_LITERAL_TRIGGER_SPEC_DECODE: &str =
    "literal create_trigger spec could not be decoded for access metadata";
const ACCOUNT_WILDCARD_KEY: &str = "account:*";
const ASSET_WILDCARD_KEY: &str = "asset:*";
const ASSET_DEF_WILDCARD_KEY: &str = "asset_def:*";
const NFT_COARSE_KEY: &str = "nft";
const AUTHORITY_ACCOUNT_KEY: &str = "account:$authority";
const AUTHORITY_PLACEHOLDER: &str = "$authority";
const TRIGGER_EVENT_PUBLIC_INPUT_KEY: &str = "trigger_event_json";
const COMPILER_FINGERPRINT: &str = concat!("kotodama_lang/", env!("CARGO_PKG_VERSION"));
#[derive(Clone, PartialEq, Eq)]
struct AccessSets {
    reads: IndexSet<String>,
    writes: IndexSet<String>,
}
impl Default for AccessSets {
    fn default() -> Self {
        Self {
            reads: IndexSet::new(),
            writes: IndexSet::new(),
        }
    }
}
impl AccessSets {
    fn union_with(&mut self, other: &Self) {
        self.reads.extend(other.reads.iter().cloned());
        self.writes.extend(other.writes.iter().cloned());
    }
}
#[derive(Clone, PartialEq, Eq)]
enum StatePathHint {
    Path(String),
    NameBase(String),
    DynamicMapChild,
}
#[derive(Clone)]
enum AccountAccessHint {
    Literal(AccountId),
    Authority,
}
#[derive(Clone, PartialEq, Eq)]
struct LiteralPointerFact {
    raw: String,
    kind: ir::DataRefKind,
    is_string_literal: bool,
}
impl StatePathHint {
    fn name_base(&self) -> Option<&str> {
        match self {
            StatePathHint::NameBase(name) => Some(name),
            StatePathHint::Path(_) | StatePathHint::DynamicMapChild => None,
        }
    }
}
struct CompilationArtifacts {
    bytes: Vec<u8>,
    compile_report: CompileReport,
    contract_interface: EmbeddedContractInterfaceV1,
}
struct LoweredCompilation {
    typed: TypedProgram,
    state_descriptors: Vec<EmbeddedStateDescriptor>,
    ir_program: ir::Program,
    executable_roots: BTreeSet<String>,
    source_name: Option<String>,
}
struct SsaCompilation {
    typed: TypedProgram,
    state_descriptors: Vec<EmbeddedStateDescriptor>,
    ssa_program: crate::ssa::Program,
    executable_roots: BTreeSet<String>,
    source_name: Option<String>,
}
struct PreparedCompilation {
    typed: TypedProgram,
    state_descriptors: Vec<EmbeddedStateDescriptor>,
    ssa_program: crate::ssa::Program,
    source_name: Option<String>,
}
struct CodegenCompilation {
    typed: TypedProgram,
    state_descriptors: Vec<EmbeddedStateDescriptor>,
    ir_program: ir::Program,
    source_name: Option<String>,
}
fn source_span(
    source_name: Option<&str>,
    location: Option<super::ast::SourceLocation>,
) -> Option<SourceSpan> {
    if source_name.is_none() && location.is_none() {
        return None;
    }
    let location = location.unwrap_or(super::ast::SourceLocation { line: 1, column: 1 });
    Some(SourceSpan {
        package_identity: None,
        source: source_name.map(ToOwned::to_owned),
        start: SourcePosition {
            line: location.line,
            column: location.column,
        },
        end: SourcePosition {
            line: location.line,
            column: location.column.saturating_add(1),
        },
        byte_range: None,
    })
}
fn native_diagnostic_bundle(
    code: &str,
    phase: DiagnosticPhase,
    source_name: Option<&str>,
    location: Option<super::ast::SourceLocation>,
    message: impl Into<String>,
) -> DiagnosticBundle {
    DiagnosticBundle::single(Diagnostic::error(
        code,
        phase,
        message,
        source_span(source_name, location),
    ))
}
fn lowering_diagnostic_bundle(
    code: &str,
    failures: Vec<ir::LoweringFailure>,
    source_name: Option<&str>,
) -> DiagnosticBundle {
    DiagnosticBundle::new(
        failures
            .into_iter()
            .map(|failure| {
                Diagnostic::error(
                    code,
                    DiagnosticPhase::Lowering,
                    failure.message,
                    source_span(source_name, Some(failure.location)),
                )
            })
            .collect(),
    )
}
#[derive(Clone)]
struct FunctionDebugSeed {
    name: String,
    location: super::ast::SourceLocation,
    source: Option<crate::source::SourceRange>,
    pc_start: u64,
    pc_end: u64,
    frame_bytes: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileReport {
    /// Canonical deployable-artifact hash used to key this sidecar.
    pub artifact_hash: iroha_crypto::Hash,
    pub source_map: Vec<EmbeddedSourceMapEntryV1>,
    /// Executed statement intervals, including original source sites of inlined helpers.
    pub statement_map: Vec<EmbeddedSourceMapEntryV1>,
    pub budget_report: Vec<EmbeddedFunctionBudgetReportV1>,
    pub access_hint_diagnostics: AccessHintDiagnostics,
}
impl CompileReport {
    /// Non-overlapping instruction ranges with statement locations and generated-code gaps.
    /// Inlined instructions retain the helper's original source location.
    #[must_use]
    pub fn symbolized_source_map(&self) -> Vec<EmbeddedSourceMapEntryV1> {
        statement_sources::complete_map(&self.source_map, &self.statement_map)
    }
    /// Render the canonical, hash-bound source-map sidecar shared by all compiler drivers.
    ///
    /// Debug information deliberately lives outside the deployable artifact.  The
    /// artifact hash in this document prevents a driver from accidentally pairing
    /// source locations with different bytecode.
    pub fn render_source_map_json(&self) -> Result<String, json::Error> {
        let entries = self
            .symbolized_source_map()
            .iter()
            .map(|entry| {
                report_json_object([
                    (
                        "source_kind",
                        json::Value::from(
                            if self
                                .statement_map
                                .binary_search_by_key(&entry.pc_start, |statement| {
                                    statement.pc_start
                                })
                                .is_ok()
                            {
                                "statement"
                            } else {
                                "function"
                            },
                        ),
                    ),
                    (
                        "function_name",
                        json::Value::from(entry.function_name.clone()),
                    ),
                    ("pc_start", json::Value::from(entry.pc_start)),
                    ("pc_end", json::Value::from(entry.pc_end)),
                    (
                        "source_path",
                        entry
                            .source
                            .source_path
                            .clone()
                            .map_or(json::Value::Null, json::Value::from),
                    ),
                    (
                        "source_id",
                        json::Value::from(u64::from(entry.source.source_id)),
                    ),
                    (
                        "byte_start",
                        json::Value::from(u64::from(entry.source.byte_start)),
                    ),
                    (
                        "byte_end",
                        json::Value::from(u64::from(entry.source.byte_end)),
                    ),
                    ("line", json::Value::from(u64::from(entry.source.line))),
                    ("column", json::Value::from(u64::from(entry.source.column))),
                ])
            })
            .collect();
        json::to_string_pretty(&report_json_object([
            ("sidecar_version", json::Value::from(1_u64)),
            ("kind", json::Value::from("source-map")),
            (
                "artifact_hash",
                json::Value::from(self.artifact_hash.to_string()),
            ),
            ("entries", json::Value::Array(entries)),
        ]))
    }
    /// Render the canonical, hash-bound compiler budget sidecar shared by all drivers.
    pub fn render_budget_json(&self) -> Result<String, json::Error> {
        let entries = self
            .budget_report
            .iter()
            .map(|entry| {
                let (source_path, source_id, byte_start, byte_end, line, column) =
                    entry.source.as_ref().map_or(
                        (
                            json::Value::Null,
                            json::Value::Null,
                            json::Value::Null,
                            json::Value::Null,
                            json::Value::Null,
                            json::Value::Null,
                        ),
                        |source| {
                            (
                                source
                                    .source_path
                                    .clone()
                                    .map_or(json::Value::Null, json::Value::from),
                                json::Value::from(u64::from(source.source_id)),
                                json::Value::from(u64::from(source.byte_start)),
                                json::Value::from(u64::from(source.byte_end)),
                                json::Value::from(u64::from(source.line)),
                                json::Value::from(u64::from(source.column)),
                            )
                        },
                    );
                report_json_object([
                    (
                        "function_name",
                        json::Value::from(entry.function_name.clone()),
                    ),
                    ("pc_start", json::Value::from(entry.pc_start)),
                    ("pc_end", json::Value::from(entry.pc_end)),
                    (
                        "bytecode_bytes",
                        json::Value::from(u64::from(entry.bytecode_bytes)),
                    ),
                    (
                        "bytecode_words",
                        json::Value::from(u64::from(entry.bytecode_words)),
                    ),
                    (
                        "frame_bytes",
                        json::Value::from(u64::from(entry.frame_bytes)),
                    ),
                    (
                        "jump_span_words",
                        json::Value::from(u64::from(entry.jump_span_words)),
                    ),
                    ("jump_range_risk", json::Value::from(entry.jump_range_risk)),
                    ("source_path", source_path),
                    ("source_id", source_id),
                    ("byte_start", byte_start),
                    ("byte_end", byte_end),
                    ("line", line),
                    ("column", column),
                ])
            })
            .collect();
        let access_hint_diagnostics = report_json_object([
            (
                "state_wildcards",
                json::Value::from(self.access_hint_diagnostics.state_wildcards as u64),
            ),
            (
                "isi_wildcards",
                json::Value::from(self.access_hint_diagnostics.isi_wildcards as u64),
            ),
            (
                "literal_trigger_spec_decode_failures",
                json::Value::from(
                    self.access_hint_diagnostics
                        .literal_trigger_spec_decode_failures as u64,
                ),
            ),
        ]);
        json::to_string_pretty(&report_json_object([
            ("sidecar_version", json::Value::from(1_u64)),
            ("kind", json::Value::from("budget")),
            (
                "artifact_hash",
                json::Value::from(self.artifact_hash.to_string()),
            ),
            ("entries", json::Value::Array(entries)),
            ("access_hint_diagnostics", access_hint_diagnostics),
        ]))
    }
}
fn report_json_object<const N: usize>(entries: [(&str, json::Value); N]) -> json::Value {
    let mut object = json::Map::new();
    for (key, value) in entries {
        object.insert(key.to_owned(), value);
    }
    json::Value::Object(object)
}
/// Diagnostics emitted when access hints cannot be fully derived.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessHintDiagnostics {
    /// Number of state accesses that could not be resolved to literal/map hints.
    pub state_wildcards: usize,
    /// Number of ISI instructions that could not be resolved to concrete hints.
    pub isi_wildcards: usize,
    /// Number of literal trigger specs that could not yield trigger access hints.
    pub literal_trigger_spec_decode_failures: usize,
}
impl AccessHintDiagnostics {
    /// Whether any access-hint fallback occurred.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state_wildcards == 0
            && self.isi_wildcards == 0
            && self.literal_trigger_spec_decode_failures == 0
    }
}
struct HintReport {
    emitted: bool,
    complete: bool,
    skipped_reasons: Vec<String>,
}
fn push_word(code: &mut Vec<u8>, word: u32) {
    code.extend_from_slice(&word.to_le_bytes());
}
fn emit_parallel_register_moves(
    code: &mut Vec<u8>,
    mut moves: Vec<(u8, u8)>,
    scratch: u8,
) -> Result<(), String> {
    moves.retain(|(destination, source)| destination != source);
    moves.sort_unstable_by_key(|(destination, source)| (*destination, *source));
    if moves
        .iter()
        .any(|(destination, source)| *destination == scratch || *source == scratch)
    {
        return Err("parallel ABI move aliases its reserved scratch register".to_owned());
    }
    if moves.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("parallel ABI move has duplicate destinations".to_owned());
    }
    while !moves.is_empty() {
        if let Some(index) = moves
            .iter()
            .position(|(destination, _)| moves.iter().all(|(_, source)| source != destination))
        {
            let (destination, source) = moves.remove(index);
            push_word(code, encode_addi(destination, source, 0)?);
            continue;
        }
        let destination = moves[0].0;
        push_word(code, encode_addi(scratch, destination, 0)?);
        for (_, source) in &mut moves {
            if *source == destination {
                *source = scratch;
            }
        }
    }
    Ok(())
}
fn emit_private_numeric_valcom_arguments(
    code: &mut Vec<u8>,
    value_register: u8,
    blind_register: u8,
    scratch: u8,
) -> Result<(), String> {
    // PRIVATE_NUMERIC_VALCOM consumes value and blinding pointers in r10/r11.
    // Treat this as a parallel assignment because register allocation may
    // legally place the two sources in the opposite ABI registers.
    emit_parallel_register_moves(
        code,
        vec![(10, value_register), (11, blind_register)],
        scratch,
    )
}
fn emit_get_private_input_arguments(
    code: &mut Vec<u8>,
    index_register: u8,
    kind: ivm_abi::private_input::PrivateInputKindV1,
    scratch: u8,
) -> Result<(), String> {
    // Move the index before writing the kind tag: the index may itself reside
    // in r11, and the tag write must not destroy it before it reaches r10.
    emit_parallel_register_moves(code, vec![(10, index_register)], scratch)?;
    let tag = i16::try_from(kind.tag()).map_err(|_| {
        format!(
            "private-input kind tag {} exceeds the V1 immediate",
            kind.tag()
        )
    })?;
    push_word(code, encode_addi(11, 0, tag)?);
    Ok(())
}
fn push_syscall(code: &mut Vec<u8>, number: u32) {
    let word = if let Ok(imm8) = u8::try_from(number) {
        encoding::wide::encode_sys(instruction::wide::system::SCALL, imm8)
    } else {
        encoding::wide::encode_syscallx(number)
    };
    push_word(code, word);
}
fn chunk_immediate(value: i64) -> i8 {
    if value > WIDE_IMM_MAX as i64 {
        WIDE_IMM_MAX as i8
    } else if value < WIDE_IMM_MIN as i64 {
        WIDE_IMM_MIN as i8
    } else {
        value as i8
    }
}
fn emit_addi_inplace(code: &mut Vec<u8>, reg: u8, mut value: i64) {
    while value != 0 {
        let chunk = chunk_immediate(value);
        push_word(
            code,
            encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, reg, reg, chunk),
        );
        value -= chunk as i64;
    }
}
fn emit_addi(code: &mut Vec<u8>, rd: u8, rs1: u8, mut value: i64) {
    if rd != rs1 {
        let first = chunk_immediate(value);
        push_word(
            code,
            encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, rd, rs1, first),
        );
        value -= i64::from(first);
    }
    if value != 0 {
        emit_addi_inplace(code, rd, value);
    }
}
fn emit_bounded_add(
    code: &mut Vec<u8>,
    fixups: &LiteralFixups,
    rd: u8,
    rs1: u8,
    value: i64,
    literal_scratch: u8,
) -> Result<(), String> {
    if ((WIDE_IMM_MIN as i64)..=(WIDE_IMM_MAX as i64)).contains(&value) {
        push_word(
            code,
            encoding::wide::encode_ri(instruction::wide::arithmetic::ADDI, rd, rs1, value as i8),
        );
        return Ok(());
    }
    if literal_scratch == rd || literal_scratch == rs1 {
        return Err("bounded add literal scratch must differ from both operands".to_owned());
    }
    emit_i64_literal_load(code, fixups, literal_scratch, value);
    push_word(
        code,
        encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, rd, rs1, literal_scratch),
    );
    Ok(())
}
fn signed_compare_plan(op: BinaryOp, left: u8, right: u8) -> Option<(u8, u8, bool)> {
    match op {
        BinaryOp::Lt => Some((left, right, false)),
        BinaryOp::Gt => Some((right, left, false)),
        BinaryOp::Le => Some((right, left, true)),
        BinaryOp::Ge => Some((left, right, true)),
        _ => None,
    }
}
fn signed_branch_plan(op: BinaryOp, left: u8, right: u8) -> Option<(u8, u8, u8)> {
    match op {
        BinaryOp::Lt => Some((0x4, left, right)),
        BinaryOp::Gt => Some((0x4, right, left)),
        BinaryOp::Le => Some((0x5, right, left)),
        BinaryOp::Ge => Some((0x5, left, right)),
        _ => None,
    }
}
/// Lay out lowering blocks so every conditional has one adjacent successor.
///
/// The iterative scheduler follows one unplaced successor when possible. If a merge-heavy or
/// backward-edge graph has already placed both successors, it splits one edge through a unique
/// adjacent jump block. The remaining edge uses one relaxed transfer, so code generation never
/// grows a conditional into a three-word branch-plus-two-jumps sequence.
fn layout_compact_branch_fallthrough(function: &mut ir::Function) -> Result<(), String> {
    let mut label_to_index = HashMap::with_capacity(function.blocks.len());
    for (index, block) in function.blocks.iter().enumerate() {
        if label_to_index.insert(block.label, index).is_some() {
            return Err(format!(
                "duplicate block label {:?} while laying out `{}`",
                block.label, function.name
            ));
        }
    }
    let entry_index = label_to_index
        .get(&function.entry)
        .copied()
        .ok_or_else(|| {
            format!(
                "missing entry block {:?} while laying out `{}`",
                function.entry, function.name
            )
        })?;
    let mut next_label = function
        .blocks
        .iter()
        .map(|block| block.label.0)
        .max()
        .and_then(|label| label.checked_add(1));
    let original_len = function.blocks.len();
    let mut blocks = std::mem::take(&mut function.blocks)
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    let mut scheduled = vec![false; original_len];
    let mut ordered = Vec::with_capacity(original_len);
    let mut heads = Vec::with_capacity(original_len);
    heads.push(entry_index);
    heads.extend((0..original_len).filter(|index| *index != entry_index));
    enum TraceAction {
        Follow(usize),
        Stop,
        Bridge { label: ir::Label, target: ir::Label },
    }
    for head in heads {
        if scheduled[head] {
            continue;
        }
        let mut current = head;
        loop {
            if scheduled[current] {
                break;
            }
            scheduled[current] = true;
            let mut block = blocks[current]
                .take()
                .expect("an original block is scheduled at most once");
            let action = match &mut block.terminator {
                Terminator::Branch {
                    then_bb, else_bb, ..
                } => {
                    let then_index = label_to_index.get(then_bb).copied().ok_or_else(|| {
                        format!(
                            "block {:?} in `{}` targets missing block {then_bb:?}",
                            block.label, function.name
                        )
                    })?;
                    let else_index = label_to_index.get(else_bb).copied().ok_or_else(|| {
                        format!(
                            "block {:?} in `{}` targets missing block {else_bb:?}",
                            block.label, function.name
                        )
                    })?;
                    let follow = [then_index, else_index]
                        .into_iter()
                        .filter(|target| !scheduled[*target])
                        .min_by_key(|target| (*target != current + 1, *target));
                    if let Some(follow) = follow {
                        TraceAction::Follow(follow)
                    } else {
                        let label = next_label.ok_or_else(|| {
                            format!(
                                "block-label space exhausted while laying out `{}`",
                                function.name
                            )
                        })?;
                        next_label = label.checked_add(1);
                        let target = *then_bb;
                        *then_bb = ir::Label(label);
                        TraceAction::Bridge {
                            label: ir::Label(label),
                            target,
                        }
                    }
                }
                Terminator::Jump(target) => {
                    let target = label_to_index.get(target).copied().ok_or_else(|| {
                        format!(
                            "block {:?} in `{}` targets missing block {target:?}",
                            block.label, function.name
                        )
                    })?;
                    if scheduled[target] {
                        TraceAction::Stop
                    } else {
                        TraceAction::Follow(target)
                    }
                }
                Terminator::Return(_) | Terminator::Return2(_, _) | Terminator::ReturnN(_) => {
                    TraceAction::Stop
                }
            };
            ordered.push(block);
            match action {
                TraceAction::Follow(next) => current = next,
                TraceAction::Stop => break,
                TraceAction::Bridge { label, target } => {
                    ordered.push(ir::BasicBlock {
                        label,
                        instrs: Vec::new(),
                        terminator: Terminator::Jump(target),
                    });
                    break;
                }
            }
        }
    }
    debug_assert!(scheduled.into_iter().all(|placed| placed));
    function.blocks = ordered;
    debug_assert_eq!(
        function.blocks.first().map(|block| block.label),
        Some(function.entry)
    );
    debug_assert!(function.blocks.windows(2).all(|pair| {
        !matches!(
            &pair[0].terminator,
            Terminator::Branch {
                then_bb,
                else_bb,
                ..
            } if pair[1].label != *then_bb && pair[1].label != *else_bb
        )
    }));
    Ok(())
}
fn emit_load64(
    code: &mut Vec<u8>,
    fixups: &LiteralFixups,
    rd: u8,
    base: u8,
    offset: i64,
    scratch: Option<u8>,
) -> Result<(), String> {
    if rd != base && ((WIDE_IMM_MIN as i64)..=(WIDE_IMM_MAX as i64)).contains(&offset) {
        push_word(code, encode_load64_rv(rd, base, offset as i16)?);
        return Ok(());
    }
    let addr_reg = if rd == base {
        scratch.ok_or_else(|| {
            format!("emit_load64 requires scratch when rd == base for offset {offset}")
        })?
    } else {
        rd
    };
    emit_bounded_add(code, fixups, addr_reg, base, offset, LITERAL_SHIFT_REG)?;
    push_word(code, encode_load64_rv(rd, addr_reg, 0)?);
    Ok(())
}
fn emit_store64(
    code: &mut Vec<u8>,
    fixups: &LiteralFixups,
    base: u8,
    rs: u8,
    offset: i64,
    scratch: u8,
) -> Result<(), String> {
    if ((WIDE_IMM_MIN as i64)..=(WIDE_IMM_MAX as i64)).contains(&offset) {
        push_word(code, encode_store64_rv(base, rs, offset as i16)?);
        return Ok(());
    }
    if scratch == base {
        return Err("emit_store64 scratch must differ from base".to_string());
    }
    emit_bounded_add(code, fixups, scratch, base, offset, LITERAL_SHIFT_REG)?;
    push_word(code, encode_store64_rv(scratch, rs, 0)?);
    Ok(())
}
fn stack_slot_offset_bytes(frame_prefix: usize, offset: usize) -> i64 {
    frame_prefix.saturating_add(offset) as i64
}
/// Reuse a scratch base across consecutive words in a stack-resident ABI table.
/// The caller reserves `register` until the table transfer is complete. A window
/// spans all 32 aligned offsets representable by the signed byte immediate.
struct StackTableWindow {
    register: u8,
    anchor: Option<i64>,
}
impl StackTableWindow {
    fn new(register: u8) -> Self {
        Self {
            register,
            anchor: None,
        }
    }

    fn address(
        &mut self,
        code: &mut Vec<u8>,
        fixups: &LiteralFixups,
        offset: usize,
    ) -> Result<(u8, i64), String> {
        let offset = i64::try_from(offset).map_err(|_| "stack table offset overflow")?;
        let sp = regalloc::SP_REG as u8;
        if let Some(anchor) = self.anchor {
            let relative = offset - anchor;
            if (i64::from(WIDE_IMM_MIN)..=i64::from(WIDE_IMM_MAX)).contains(&relative) {
                return Ok((self.register, relative));
            }
        } else if (i64::from(WIDE_IMM_MIN)..=i64::from(WIDE_IMM_MAX)).contains(&offset) {
            return Ok((sp, offset));
        }
        let anchor = offset
            .checked_sub(i64::from(WIDE_IMM_MIN))
            .ok_or("stack table window overflow")?;
        emit_bounded_add(code, fixups, self.register, sp, anchor, LITERAL_SHIFT_REG)?;
        self.anchor = Some(anchor);
        Ok((self.register, i64::from(WIDE_IMM_MIN)))
    }
}
fn encode_nop() -> u32 {
    encode_addi(0, 0, 0).expect("ADDI x0, x0, 0 must always encode")
}
fn write_word(code: &mut [u8], at: usize, word: u32) {
    code[at..at + 4].copy_from_slice(&word.to_le_bytes());
}
fn reserve_word(code: &mut Vec<u8>) -> usize {
    let start = code.len();
    push_word(code, encode_nop());
    start
}
fn transfer_offset(start: usize, target: usize, kind: &str) -> Result<i64, String> {
    let start = i64::try_from(start).map_err(|_| format!("{kind} source offset is too large"))?;
    let target = i64::try_from(target).map_err(|_| format!("{kind} target offset is too large"))?;
    let off = target - start;
    if (off % 4) != 0 {
        return Err(format!("unaligned {kind} offset {off} at {start}"));
    }
    Ok(off)
}
fn encode_long_transfer(op: u8, offset: i64, kind: &str) -> Result<u32, String> {
    let offset_words = offset / 4;
    if !(-0x80_0000..=0x7f_ffff).contains(&offset_words) {
        return Err(format!(
            "{kind} offset {offset} exceeds signed 24-bit word range"
        ));
    }
    Ok(encoding::wide::encode_offset24(op, offset_words as i32))
}
fn patch_jump_transfer(code: &mut [u8], start: usize, target: usize) -> Result<(), String> {
    let offset = transfer_offset(start, target, "jump")?;
    let word = if let Ok(offset) = i32::try_from(offset)
        && let Ok(jal) = encode_jal(0, offset)
    {
        jal
    } else {
        encode_long_transfer(instruction::wide::control::JMP, offset, "jump")?
    };
    write_word(code, start, word);
    Ok(())
}
fn patch_trampoline_jump(code: &mut [u8], start: usize, target: usize) -> Result<(), String> {
    let offset = transfer_offset(start, target, "trampoline jump")?;
    let word = encode_long_transfer(instruction::wide::control::JMP, offset, "trampoline jump")?;
    write_word(code, start, word);
    Ok(())
}
fn patch_call_transfer(code: &mut [u8], start: usize, target: usize) -> Result<(), String> {
    let offset = transfer_offset(start, target, "call")?;
    let word = if let Ok(offset) = i32::try_from(offset)
        && let Ok(jal) = encode_jal(1, offset)
    {
        jal
    } else {
        encode_long_transfer(instruction::wide::control::JALS, offset, "call")?
    };
    write_word(code, start, word);
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferKind {
    Jump,
    Call,
}
#[derive(Clone, Copy, Debug)]
struct DeferredTransfer {
    at: usize,
    target: usize,
    kind: TransferKind,
}
fn patch_or_defer_transfer(
    code: &mut [u8],
    at: usize,
    target: usize,
    kind: TransferKind,
    deferred: &mut Vec<DeferredTransfer>,
) -> Result<(), String> {
    let offset = transfer_offset(
        at,
        target,
        match kind {
            TransferKind::Jump => "jump",
            TransferKind::Call => "call",
        },
    )?;
    let direct = i32::try_from(offset)
        .ok()
        .and_then(|offset| encode_jal(u8::from(kind == TransferKind::Call), offset).ok())
        .or_else(|| {
            encode_long_transfer(
                match kind {
                    TransferKind::Jump => instruction::wide::control::JMP,
                    TransferKind::Call => instruction::wide::control::JALS,
                },
                offset,
                match kind {
                    TransferKind::Jump => "jump",
                    TransferKind::Call => "call",
                },
            )
            .ok()
        });
    if let Some(word) = direct {
        write_word(code, at, word);
    } else {
        // The final relaxation pass replaces this placeholder with a direct
        // transfer to the first sparse trampoline island.
        write_word(code, at, encode_nop());
        deferred.push(DeferredTransfer { at, target, kind });
    }
    Ok(())
}
const TRAMPOLINE_ISLAND_BYTES: usize = 8;
const TRAMPOLINE_HOP_BYTES: usize = 4 * 1024 * 1024;
#[derive(Clone, Copy, Debug)]
enum ControlRelocationKind {
    Conditional(u32),
    Transfer(TransferKind),
}
#[derive(Clone, Copy, Debug)]
struct ControlRelocation {
    at: usize,
    target: usize,
    kind: ControlRelocationKind,
    deferred: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct TrampolineIsland {
    boundary: usize,
    relocation: usize,
    ordinal: usize,
}
#[derive(Clone, Debug)]
struct CodeOffsetMap {
    islands: Vec<TrampolineIsland>,
}
impl CodeOffsetMap {
    fn islands_before(&self, offset: usize) -> usize {
        self.islands
            .partition_point(|island| island.boundary < offset)
    }
    fn islands_through(&self, offset: usize) -> usize {
        self.islands
            .partition_point(|island| island.boundary <= offset)
    }
    /// Map a control-flow entry boundary. Islands at the boundary execute
    /// their skip words before reaching the original instruction.
    fn entry(&self, offset: usize) -> usize {
        offset.saturating_add(
            self.islands_before(offset)
                .saturating_mul(TRAMPOLINE_ISLAND_BYTES),
        )
    }
    /// Map the original instruction at a boundary, after any inserted islands.
    fn instruction(&self, offset: usize) -> usize {
        offset.saturating_add(
            self.islands_through(offset)
                .saturating_mul(TRAMPOLINE_ISLAND_BYTES),
        )
    }
    fn island_instruction(&self, island: TrampolineIsland) -> usize {
        let index = self
            .islands
            .binary_search(&island)
            .expect("trampoline island belongs to this offset map");
        island
            .boundary
            .saturating_add(index.saturating_mul(TRAMPOLINE_ISLAND_BYTES))
            .saturating_add(4)
    }
}
fn decoded_control_target(at: usize, offset_words: i64) -> Result<usize, String> {
    let byte_offset = offset_words
        .checked_mul(4)
        .ok_or_else(|| format!("control-flow offset overflows at {at}"))?;
    let target = i128::try_from(at)
        .expect("usize always fits i128")
        .checked_add(i128::from(byte_offset))
        .and_then(|target| usize::try_from(target).ok())
        .ok_or_else(|| format!("control-flow target is outside the code image at {at}"))?;
    Ok(target)
}
fn scan_control_relocations(
    code: &[u8],
    deferred: &[DeferredTransfer],
) -> Result<Vec<ControlRelocation>, String> {
    if !code.len().is_multiple_of(4) {
        return Err("Kotodama code image is not word-aligned".to_owned());
    }
    let deferred_by_offset = deferred
        .iter()
        .map(|fixup| (fixup.at, *fixup))
        .collect::<HashMap<_, _>>();
    if deferred_by_offset.len() != deferred.len() {
        return Err("duplicate deferred control-transfer source".to_owned());
    }
    if let Some(fixup) = deferred.iter().find(|fixup| {
        !fixup.at.is_multiple_of(4)
            || !fixup.target.is_multiple_of(4)
            || fixup.at >= code.len()
            || fixup.target >= code.len()
    }) {
        return Err(format!(
            "deferred control transfer {} -> {} is outside the aligned code image",
            fixup.at, fixup.target
        ));
    }
    let mut relocations = Vec::new();
    for at in (0..code.len()).step_by(4) {
        if let Some(fixup) = deferred_by_offset.get(&at) {
            relocations.push(ControlRelocation {
                at,
                target: fixup.target,
                kind: ControlRelocationKind::Transfer(fixup.kind),
                deferred: true,
            });
            continue;
        }
        let word = u32::from_le_bytes(
            code[at..at + 4]
                .try_into()
                .expect("word-aligned code slice"),
        );
        let opcode = instruction::wide::opcode(word);
        let (offset_words, kind) = match opcode {
            instruction::wide::control::BEQ
            | instruction::wide::control::BNE
            | instruction::wide::control::BLT
            | instruction::wide::control::BGE
            | instruction::wide::control::BLTU
            | instruction::wide::control::BGEU => (
                i64::from(instruction::wide::imm8(word)),
                ControlRelocationKind::Conditional(word),
            ),
            instruction::wide::control::JAL => (
                i64::from(instruction::wide::imm16(word)),
                ControlRelocationKind::Transfer(if instruction::wide::rd(word) == 0 {
                    TransferKind::Jump
                } else {
                    TransferKind::Call
                }),
            ),
            instruction::wide::control::JMP => (
                i64::from(instruction::wide::imm24(word)),
                ControlRelocationKind::Transfer(TransferKind::Jump),
            ),
            instruction::wide::control::JALS => (
                i64::from(instruction::wide::imm24(word)),
                ControlRelocationKind::Transfer(TransferKind::Call),
            ),
            _ => continue,
        };
        relocations.push(ControlRelocation {
            at,
            target: decoded_control_target(at, offset_words)?,
            kind,
            deferred: false,
        });
    }
    Ok(relocations)
}
fn transfer_fits_signed24(start: usize, target: usize) -> bool {
    transfer_offset(start, target, "transfer")
        .ok()
        .and_then(|offset| {
            encode_long_transfer(instruction::wide::control::JMP, offset, "transfer").ok()
        })
        .is_some()
}
fn conditional_insertion_forbidden(boundary: usize, relocations: &[ControlRelocation]) -> bool {
    relocations.iter().any(|relocation| {
        if !matches!(relocation.kind, ControlRelocationKind::Conditional(_)) {
            return false;
        }
        let lower = relocation.at.min(relocation.target);
        let upper = relocation.at.max(relocation.target);
        lower <= boundary && boundary <= upper
    })
}
fn choose_trampoline_boundary(
    mut boundary: usize,
    forward: bool,
    lower: usize,
    upper: usize,
    relocations: &[ControlRelocation],
) -> Result<usize, String> {
    boundary -= boundary % 4;
    while conditional_insertion_forbidden(boundary, relocations) {
        boundary = if forward {
            boundary.checked_add(4)
        } else {
            boundary.checked_sub(4)
        }
        .ok_or_else(|| "trampoline boundary search overflowed".to_owned())?;
    }
    if boundary <= lower || boundary >= upper {
        return Err(format!(
            "cannot place a far-transfer trampoline between {lower} and {upper}"
        ));
    }
    Ok(boundary)
}
fn route_boundaries(
    relocation: &ControlRelocation,
    relocations: &[ControlRelocation],
    hop_bytes: usize,
) -> Result<Vec<usize>, String> {
    let forward = relocation.target > relocation.at;
    let lower = relocation.at.min(relocation.target);
    let upper = relocation.at.max(relocation.target);
    let mut cursor = relocation.at;
    let mut boundaries = Vec::new();
    while cursor.abs_diff(relocation.target) > hop_bytes {
        let desired = if forward {
            cursor
                .checked_add(hop_bytes)
                .ok_or_else(|| "forward trampoline route overflowed".to_owned())?
        } else {
            cursor
                .checked_sub(hop_bytes)
                .ok_or_else(|| "backward trampoline route overflowed".to_owned())?
        };
        let boundary = choose_trampoline_boundary(desired, forward, lower, upper, relocations)?;
        if boundaries.last().copied() == Some(boundary) {
            return Err("far-transfer trampoline route did not make progress".to_owned());
        }
        boundaries.push(boundary);
        cursor = boundary;
    }
    if boundaries.is_empty() {
        let midpoint = lower + (upper - lower) / 2;
        boundaries.push(choose_trampoline_boundary(
            midpoint,
            forward,
            lower,
            upper,
            relocations,
        )?);
    }
    Ok(boundaries)
}
fn relax_control_transfers_with_trampolines(
    code: Vec<u8>,
    deferred: &[DeferredTransfer],
    hop_bytes: usize,
) -> Result<(Vec<u8>, CodeOffsetMap), String> {
    if hop_bytes < 8 || !hop_bytes.is_multiple_of(4) {
        return Err("trampoline hop size must be a word-aligned value of at least 8".to_owned());
    }
    let relocations = scan_control_relocations(&code, deferred)?;
    let mut routed = relocations
        .iter()
        .enumerate()
        .filter_map(|(index, relocation)| {
            let ControlRelocationKind::Transfer(_) = relocation.kind else {
                return None;
            };
            (relocation.deferred || !transfer_fits_signed24(relocation.at, relocation.target))
                .then_some(index)
        })
        .collect::<BTreeSet<_>>();
    let offset_map = loop {
        let mut islands = Vec::new();
        for &relocation_index in &routed {
            let boundaries =
                route_boundaries(&relocations[relocation_index], &relocations, hop_bytes)?;
            for (ordinal, boundary) in boundaries.iter().copied().enumerate() {
                islands.push(TrampolineIsland {
                    boundary,
                    relocation: relocation_index,
                    ordinal,
                });
            }
        }
        islands.sort_unstable();
        let offset_map = CodeOffsetMap { islands };
        let mut newly_routed = Vec::new();
        for (index, relocation) in relocations.iter().enumerate() {
            if routed.contains(&index)
                || !matches!(relocation.kind, ControlRelocationKind::Transfer(_))
            {
                continue;
            }
            if !transfer_fits_signed24(
                offset_map.instruction(relocation.at),
                offset_map.entry(relocation.target),
            ) {
                newly_routed.push(index);
            }
        }
        if newly_routed.is_empty() {
            break offset_map;
        }
        routed.extend(newly_routed);
    };
    let mut island_positions_with_ordinals = vec![Vec::new(); relocations.len()];
    for island in &offset_map.islands {
        island_positions_with_ordinals[island.relocation]
            .push((island.ordinal, offset_map.island_instruction(*island)));
    }
    let island_positions = island_positions_with_ordinals
        .into_iter()
        .map(|mut positions| {
            positions.sort_unstable_by_key(|(ordinal, _)| *ordinal);
            positions
                .into_iter()
                .map(|(_, position)| position)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut relaxed = Vec::with_capacity(
        code.len()
            .saturating_add(offset_map.islands.len() * TRAMPOLINE_ISLAND_BYTES),
    );
    let mut island_cursor = 0usize;
    for at in (0..code.len()).step_by(4) {
        while offset_map
            .islands
            .get(island_cursor)
            .is_some_and(|island| island.boundary == at)
        {
            push_word(
                &mut relaxed,
                encode_jal(0, 8).expect("two-word trampoline skip always fits JAL"),
            );
            push_word(&mut relaxed, encode_nop());
            island_cursor += 1;
        }
        relaxed.extend_from_slice(&code[at..at + 4]);
    }
    if island_cursor != offset_map.islands.len() {
        return Err("trampoline route points outside the code image".to_owned());
    }
    for (index, relocation) in relocations.iter().enumerate() {
        let source = offset_map.instruction(relocation.at);
        match relocation.kind {
            ControlRelocationKind::Conditional(word) => {
                let target = offset_map.entry(relocation.target);
                let byte_offset = transfer_offset(source, target, "conditional branch")?;
                let word_offset = byte_offset / 4;
                let word_offset = i8::try_from(word_offset).map_err(|_| {
                    format!(
                        "conditional branch at {source} exceeds signed 8-bit word range after trampoline relaxation"
                    )
                })?;
                write_word(
                    &mut relaxed,
                    source,
                    encoding::wide::encode_branch(
                        instruction::wide::opcode(word),
                        u8::try_from(instruction::wide::rd(word))
                            .expect("decoded wide destination register fits u8"),
                        u8::try_from(instruction::wide::rs1(word))
                            .expect("decoded wide source register fits u8"),
                        word_offset,
                    ),
                );
            }
            ControlRelocationKind::Transfer(kind) => {
                let target = island_positions[index]
                    .first()
                    .copied()
                    .unwrap_or_else(|| offset_map.entry(relocation.target));
                match kind {
                    TransferKind::Jump => patch_jump_transfer(&mut relaxed, source, target)?,
                    TransferKind::Call => patch_call_transfer(&mut relaxed, source, target)?,
                }
                for (ordinal, island) in island_positions[index].iter().copied().enumerate() {
                    let target = island_positions[index]
                        .get(ordinal + 1)
                        .copied()
                        .unwrap_or_else(|| offset_map.entry(relocation.target));
                    patch_trampoline_jump(&mut relaxed, island, target)?;
                }
            }
        }
    }
    Ok((relaxed, offset_map))
}
fn patch_indexed_literal_load(
    code: &mut [u8],
    start: usize,
    rd: u8,
    index: u16,
    kind: LiteralKindV1,
) {
    let opcode = match kind {
        LiteralKindV1::PointerTlv => instruction::wide::memory::LDLIT,
        LiteralKindV1::I64 => instruction::wide::memory::LDI64,
    };
    write_word(
        code,
        start,
        encoding::wide::encode_literal(opcode, rd, index),
    );
}
#[cfg(test)]
fn patch_literal_load(code: &mut [u8], start: usize, rd: u8, index: u16) {
    patch_indexed_literal_load(code, start, rd, index, LiteralKindV1::PointerTlv);
}
fn emit_literal_load(code: &mut Vec<u8>, fixups: &LiteralFixups, rd: u8, key: DataKey) {
    let off = reserve_word(code);
    fixups.borrow_mut().push((off, rd, key));
}
fn emit_i64_literal_load(code: &mut Vec<u8>, fixups: &LiteralFixups, rd: u8, value: i64) {
    emit_literal_load(code, fixups, rd, DataKey(DataKind::I64, value.to_string()));
}
fn validate_literal_count(count: usize) -> Result<(), String> {
    if count > usize::from(u16::MAX) + 1 {
        return Err(format!(
            "too many unique literals: {count}; indexed literal loads support at most {}",
            usize::from(u16::MAX) + 1
        ));
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum DataKind {
    I64,
    Account,
    AssetDef,
    NftId,
    AssetId,
    Name,
    Json,
    Domain,
    String,
    Blob,
    NoritoBytes,
    DataSpaceId,
    AxtDescriptor,
    AxtAnchoredSpendV1,
    ProofBlob,
    SoracloudRequest,
    SoracloudResponse,
    Int,
    Decimal,
    Quantity,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct DataKey(DataKind, String);
type LiteralFixup = (usize, u8, DataKey);
type LiteralFixups = RefCell<Vec<LiteralFixup>>;
impl DataKind {
    const fn literal_kind(self) -> LiteralKindV1 {
        match self {
            Self::I64 => LiteralKindV1::I64,
            Self::Account
            | Self::AssetDef
            | Self::NftId
            | Self::AssetId
            | Self::Name
            | Self::Json
            | Self::Domain
            | Self::String
            | Self::Blob
            | Self::NoritoBytes
            | Self::DataSpaceId
            | Self::AxtDescriptor
            | Self::AxtAnchoredSpendV1
            | Self::ProofBlob
            | Self::SoracloudRequest
            | Self::SoracloudResponse
            | Self::Int
            | Self::Decimal
            | Self::Quantity => LiteralKindV1::PointerTlv,
        }
    }
}
fn pointer_type_for_kind(kind: ir::DataRefKind) -> Option<PointerType> {
    use ir::DataRefKind::*;
    match kind {
        Account => Some(PointerType::AccountId),
        AssetDef => Some(PointerType::AssetDefinitionId),
        Name => Some(PointerType::Name),
        Json => Some(PointerType::Json),
        NftId => Some(PointerType::NftId),
        AssetId => Some(PointerType::AssetId),
        Domain => Some(PointerType::DomainId),
        Blob => Some(PointerType::Blob),
        NoritoBytes => Some(PointerType::NoritoBytes),
        DataSpaceId => Some(PointerType::DataSpaceId),
        AxtDescriptor => Some(PointerType::AxtDescriptor),
        AxtAnchoredSpendV1 => Some(PointerType::AxtAnchoredSpendV1),
        ProofBlob => Some(PointerType::ProofBlob),
        SoracloudRequest => Some(PointerType::SoracloudRequest),
        SoracloudResponse => Some(PointerType::SoracloudResponse),
        Int => Some(PointerType::Int),
        Decimal => Some(PointerType::Decimal),
        Quantity => Some(PointerType::Quantity),
    }
}
fn data_key_for_pointer(kind: ir::DataRefKind, value: &str) -> DataKey {
    use ir::DataRefKind::*;
    match kind {
        Account => DataKey(DataKind::Account, value.to_owned()),
        AssetDef => DataKey(DataKind::AssetDef, value.to_owned()),
        Name => DataKey(DataKind::Name, value.to_owned()),
        Json => DataKey(DataKind::Json, value.to_owned()),
        NftId => DataKey(DataKind::NftId, value.to_owned()),
        AssetId => DataKey(DataKind::AssetId, value.to_owned()),
        Domain => DataKey(DataKind::Domain, value.to_owned()),
        Blob => DataKey(DataKind::Blob, value.to_owned()),
        NoritoBytes => DataKey(DataKind::NoritoBytes, value.to_owned()),
        DataSpaceId => DataKey(DataKind::DataSpaceId, value.to_owned()),
        AxtDescriptor => DataKey(DataKind::AxtDescriptor, value.to_owned()),
        AxtAnchoredSpendV1 => DataKey(DataKind::AxtAnchoredSpendV1, value.to_owned()),
        ProofBlob => DataKey(DataKind::ProofBlob, value.to_owned()),
        SoracloudRequest => DataKey(DataKind::SoracloudRequest, value.to_owned()),
        SoracloudResponse => DataKey(DataKind::SoracloudResponse, value.to_owned()),
        Int => DataKey(DataKind::Int, value.to_owned()),
        Decimal => DataKey(DataKind::Decimal, value.to_owned()),
        Quantity => DataKey(DataKind::Quantity, value.to_owned()),
    }
}
fn quantity_literal_data_key(
    func_idx: usize,
    value: ir::Temp,
    string_map: &HashMap<(usize, ir::Temp), String>,
    dataref_kind_map: &HashMap<(usize, ir::Temp), ir::DataRefKind>,
) -> Result<Option<DataKey>, String> {
    let Some(raw) = string_map.get(&(func_idx, value)) else {
        return Ok(None);
    };
    match dataref_kind_map.get(&(func_idx, value)) {
        Some(ir::DataRefKind::Quantity) => Ok(Some(DataKey(DataKind::Quantity, raw.clone()))),
        other => Err(format!(
            "quantity host boundary received compiler literal `{raw}` with pointer kind {other:?}"
        )),
    }
}
fn decode_hex_or_raw_bytes(raw: &str) -> Result<Vec<u8>, String> {
    if let Some(trimmed) = raw.strip_prefix("0x") {
        if trimmed.len() % 2 == 0 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut out = Vec::with_capacity(trimmed.len() / 2);
            for chunk in trimmed.as_bytes().chunks(2) {
                let byte_str = std::str::from_utf8(chunk)
                    .map_err(|e| format!("invalid hex literal `{raw}`: {e}"))?;
                let byte = u8::from_str_radix(byte_str, 16)
                    .map_err(|e| format!("invalid hex literal `{raw}`: {e}"))?;
                out.push(byte);
            }
            return Ok(out);
        }
        return Err(format!(
            "invalid hex literal `{raw}`: expected even-length hex digits"
        ));
    }
    Ok(raw.as_bytes().to_vec())
}
fn state_path_literal_data_key(
    func_idx: usize,
    path: ir::Temp,
    string_map: &HashMap<(usize, ir::Temp), String>,
    dataref_kind_map: &HashMap<(usize, ir::Temp), ir::DataRefKind>,
) -> Result<Option<DataKey>, String> {
    let Some(raw) = string_map.get(&(func_idx, path)) else {
        return Ok(None);
    };
    match dataref_kind_map.get(&(func_idx, path)) {
        Some(ir::DataRefKind::NoritoBytes)
            if state_path_from_norito_literal(raw).is_some() =>
        {
            Ok(Some(DataKey(DataKind::NoritoBytes, raw.clone())))
        }
        Some(ir::DataRefKind::NoritoBytes) => Err(
            "durable state syscall received literal NoritoBytes that do not contain a canonical StatePath"
                .to_owned(),
        ),
        other => Err(format!(
            "durable state syscall received compiler literal `{raw}` with pointer kind {other:?}; expected NoritoBytes(StatePath)"
        )),
    }
}
fn encode_pointer_tlv_bytes(
    kind: ir::DataRefKind,
    raw: &str,
    is_string_literal: bool,
) -> Option<Vec<u8>> {
    use ir::DataRefKind as DRK;
    use iroha_primitives::json::Json;
    let (type_id, payload) = match kind {
        DRK::Account => {
            let id = iroha_data_model::account::AccountId::parse_encoded(raw).ok()?;
            (
                PointerType::AccountId,
                ivm_abi::codec::encode_canonical_norito(&id).ok()?,
            )
        }
        DRK::AssetDef => {
            let id: iroha_data_model::asset::AssetDefinitionId = raw.parse().ok()?;
            (
                PointerType::AssetDefinitionId,
                ivm_abi::codec::encode_canonical_norito(&id).ok()?,
            )
        }
        DRK::AssetId => {
            let id: iroha_data_model::asset::AssetId = raw.parse().ok()?;
            (
                PointerType::AssetId,
                ivm_abi::codec::encode_canonical_norito(&id).ok()?,
            )
        }
        DRK::NftId => {
            let id: iroha_data_model::nft::NftId = raw.parse().ok()?;
            (
                PointerType::NftId,
                ivm_abi::codec::encode_canonical_norito(&id).ok()?,
            )
        }
        DRK::Name => {
            let nm: iroha_model_base::name::Name = raw.parse().ok()?;
            (
                PointerType::Name,
                ivm_abi::codec::encode_canonical_norito(&nm).ok()?,
            )
        }
        DRK::Domain => {
            let id = iroha_model_base::domain::DomainId::parse_fully_qualified(raw).ok()?;
            (
                PointerType::DomainId,
                ivm_abi::codec::encode_canonical_norito(&id).ok()?,
            )
        }
        DRK::Json => {
            let json = Json::from_str_norito(raw).ok()?;
            (
                PointerType::Json,
                ivm_abi::codec::encode_canonical_norito(&json).ok()?,
            )
        }
        DRK::Blob if is_string_literal => (PointerType::Blob, raw.as_bytes().to_vec()),
        DRK::Blob => (PointerType::Blob, decode_hex_or_raw_bytes(raw).ok()?),
        DRK::NoritoBytes => (PointerType::NoritoBytes, decode_hex_or_raw_bytes(raw).ok()?),
        DRK::Int => {
            let value = raw.parse::<iroha_primitives::bigint::BigInt>().ok()?;
            let frame = iroha_primitives::numeric_abi::IntValueV1::try_new(value)
                .ok()?
                .encode_frame()
                .ok()?;
            (PointerType::Int, frame)
        }
        DRK::Decimal => {
            let value = raw
                .parse::<iroha_primitives::numeric::Numeric>()
                .ok()?
                .canonicalize_decimal()
                .ok()?;
            let frame = iroha_primitives::numeric_abi::DecimalValueV1::try_from_numeric(value)
                .ok()?
                .encode_frame()
                .ok()?;
            (PointerType::Decimal, frame)
        }
        DRK::Quantity => {
            let decimal = raw
                .parse::<iroha_primitives::numeric::Numeric>()
                .ok()?
                .canonicalize_decimal()
                .ok()?;
            let quantity = iroha_primitives::numeric::Quantity::try_from_numeric(decimal).ok()?;
            let frame = iroha_primitives::numeric_abi::QuantityValueV1::new(quantity)
                .encode_frame()
                .ok()?;
            (PointerType::Quantity, frame)
        }
        DRK::DataSpaceId => {
            if let Some(raw_id) = parse_u64_literal(raw) {
                let id = iroha_model_base::topology::DataSpaceId::new(raw_id);
                (
                    PointerType::DataSpaceId,
                    ivm_abi::codec::encode_canonical_norito(&id).ok()?,
                )
            } else {
                let bytes = decode_hex_or_raw_bytes(raw).ok()?;
                let value: iroha_model_base::topology::DataSpaceId =
                    ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
                (
                    PointerType::DataSpaceId,
                    ivm_abi::codec::encode_canonical_norito(&value).ok()?,
                )
            }
        }
        DRK::AxtDescriptor => {
            let bytes = decode_hex_or_raw_bytes(raw).ok()?;
            let value: crate::axt::AxtDescriptor =
                ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
            crate::axt::validate_descriptor(&value).ok()?;
            (
                PointerType::AxtDescriptor,
                ivm_abi::codec::encode_canonical_norito(&value).ok()?,
            )
        }
        DRK::AxtAnchoredSpendV1 => {
            let bytes = decode_hex_or_raw_bytes(raw).ok()?;
            let value: iroha_data_model::nexus::AxtAnchoredSpendV1 =
                ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
            value.issuer_payload_v1().ok()?;
            (
                PointerType::AxtAnchoredSpendV1,
                ivm_abi::codec::encode_canonical_norito(&value).ok()?,
            )
        }
        DRK::ProofBlob => {
            let bytes = decode_hex_or_raw_bytes(raw).ok()?;
            let value: crate::axt::ProofBlob =
                ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
            crate::axt::validate_proof_blob(&value).ok()?;
            (
                PointerType::ProofBlob,
                ivm_abi::codec::encode_canonical_norito(&value).ok()?,
            )
        }
        DRK::SoracloudRequest => {
            let bytes = decode_hex_or_raw_bytes(raw).ok()?;
            let value: iroha_data_model::soracloud::SoracloudHostRequestEnvelopeV1 =
                ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
            value.validate().ok()?;
            (
                PointerType::SoracloudRequest,
                ivm_abi::codec::encode_canonical_norito(&value).ok()?,
            )
        }
        DRK::SoracloudResponse => {
            let bytes = decode_hex_or_raw_bytes(raw).ok()?;
            let value: iroha_data_model::soracloud::SoracloudHostResponseEnvelopeV1 =
                ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
            value.validate().ok()?;
            (
                PointerType::SoracloudResponse,
                ivm_abi::codec::encode_canonical_norito(&value).ok()?,
            )
        }
    };
    let mut out = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
    out.extend_from_slice(&(type_id as u16).to_be_bytes());
    out.push(1u8);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    let h: [u8; 32] = iroha_crypto::Hash::new(&payload).into();
    out.extend_from_slice(&h);
    Some(out)
}
fn parse_u64_literal(raw: &str) -> Option<u64> {
    if let Some(hex) = raw.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u64>().ok()
    }
}
// Kotodama ZK capabilities are supported by semantic/IR lowering:
//   - namespaced verification operations lower to their typed ABI-v1 syscalls;
//   - namespaced governance operations build their exact instruction payloads
//     inside the compiler before host submission.
// Raw instruction submission and direct syscall spellings are not source APIs.
// See `kotodama::semantic`, `kotodama::ir`, and the sample
// `crates/kotodama_lang/src/samples/zk_vote_ballot.ko`.
/// Compiler entry point for translating KOTODAMA programs into IVM bytecode.
#[derive(Clone)]
pub struct Compiler {
    lang: Language,
    opts: CompilerOptions,
}
impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}
/// Build mode accepted by the compiler driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerMode {
    Production,
    Test,
}
/// Caller-selectable deployment policy.
#[derive(Clone, Debug)]
pub struct CompilerOptions {
    /// Force ZK mode bit in header even if program does not use ZK opcodes.
    pub force_zk: bool,
    /// Maximum execution cycles to encode in the artifact header.
    pub max_cycles: u64,
    /// Chain discriminant used to validate and lower canonical account literals.
    ///
    /// Capturing this in compiler policy keeps offline builds deterministic and
    /// prevents a cached artifact accepted for one network from being reused
    /// under another network's account-literal policy.
    pub chain_discriminant: u16,
    /// Selects production artifact compilation or explicit local-test compilation.
    ///
    /// Production mode rejects test declarations and test-capable typed HIR; it never silently
    /// strips them from a deployable artifact. Test mode emits an ABI-authenticated generic IVM 1.1
    /// harness without a deployable CNTR section.
    pub mode: CompilerMode,
}
impl Default for CompilerOptions {
    fn default() -> Self {
        Self {
            force_zk: false,
            max_cycles: DEFAULT_MAX_CYCLES,
            chain_discriminant: iroha_data_model::account::address::chain_discriminant(),
            mode: CompilerMode::Production,
        }
    }
}
#[cfg(test)]
#[path = "compiler/tests.rs"]
mod tests;
/// Convenience wrapper for encoding `rd = rs1 + rs2` using the canonical wide layout.
pub fn encode_add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, rd, rs1, rs2)
}
/// Encode `rd = rs1 + imm` using the canonical wide register–immediate format.
///
/// This helper is primarily used by the Kotodama code generator to materialize
/// small constants (e.g., `rd = imm` via `rs1 = x0`). Kotodama targets IVM
/// bytecode; the wide layout is the on-chain representation for the first release.
///
/// Example
/// -------
///
/// ```
/// use kotodama_lang::compiler::encode_addi;
/// let word = encode_addi(1, 1, 7).expect("addi"); // addi x1, x1, 7
/// assert_eq!(word, 0x2001_0107);
/// ```
pub fn encode_addi(rd: u8, rs1: u8, imm: i16) -> Result<u32, String> {
    if !(WIDE_IMM_MIN..=WIDE_IMM_MAX).contains(&(imm as i32)) {
        return Err(format!(
            "encode_addi immediate {imm} out of range; use emit_addi for chunked emission"
        ));
    }
    Ok(encoding::wide::encode_ri(
        instruction::wide::arithmetic::ADDI,
        rd,
        rs1,
        imm as i8,
    ))
}
/// Encode a 64-bit load (`rd <- [rs1 + imm]`) using the canonical wide layout.
#[inline]
pub fn encode_load64_rv(rd: u8, rs1: u8, imm: i16) -> Result<u32, String> {
    if !(WIDE_IMM_MIN..=WIDE_IMM_MAX).contains(&(imm as i32)) {
        return Err(format!(
            "encode_load64_rv offset {imm} out of wide range; use emit_load64"
        ));
    }
    Ok(encoding::wide::encode_load(
        instruction::wide::memory::LOAD64,
        rd,
        rs1,
        imm as i8,
    ))
}
/// Encode a 64-bit store (`[rs1 + imm] <- rs2`) using the canonical wide layout.
#[inline]
pub fn encode_store64_rv(rs1: u8, rs2: u8, imm: i16) -> Result<u32, String> {
    if !(WIDE_IMM_MIN..=WIDE_IMM_MAX).contains(&(imm as i32)) {
        return Err(format!(
            "encode_store64_rv offset {imm} out of wide range; use emit_store64"
        ));
    }
    Ok(encoding::wide::encode_store(
        instruction::wide::memory::STORE64,
        rs1,
        rs2,
        imm as i8,
    ))
}
/// Encode a branch using the canonical wide layout. `funct3` selects the branch condition.
/// Encoding for B‑type branches (BEQ/BNE/BLT/BGE/BLTU/BGEU).
pub fn encode_branch_rv(funct3: u8, rs1: u8, rs2: u8, imm: i16) -> Result<u32, String> {
    if (imm & 0x3) != 0 {
        return Err(format!(
            "encode_branch_rv requires word-aligned offset, got {imm}"
        ));
    }
    let offset_words = (imm / 4) as i32;
    if !(WIDE_IMM_MIN..=WIDE_IMM_MAX).contains(&offset_words) {
        return Err(format!(
            "encode_branch_rv offset {imm} out of wide range; use emit_branch"
        ));
    }
    let op = match funct3 {
        0x0 => instruction::wide::control::BEQ,
        0x1 => instruction::wide::control::BNE,
        0x4 => instruction::wide::control::BLT,
        0x5 => instruction::wide::control::BGE,
        0x6 => instruction::wide::control::BLTU,
        0x7 => instruction::wide::control::BGEU,
        other => {
            return Err(format!("unsupported branch funct3 {other}"));
        }
    };
    Ok(encoding::wide::encode_branch(
        op,
        rs1,
        rs2,
        offset_words as i8,
    ))
}
/// Encode a jump-and-link (`JAL`) in the canonical wide layout. Use `rd = 0` for a plain jump.
pub fn encode_jal(rd: u8, imm: i32) -> Result<u32, String> {
    if (imm % 4) != 0 {
        return Err(format!(
            "encode_jal requires word-aligned offset, got {imm}"
        ));
    }
    let offset_words = imm / 4;
    if !(-0x8000..=0x7fff).contains(&offset_words) {
        return Err(format!("encode_jal offset {imm} exceeds 16-bit word range"));
    }
    Ok(encoding::wide::encode_jump(
        instruction::wide::control::JAL,
        rd,
        offset_words as i16,
    ))
}
#[cfg(test)]
mod test_mode_tests {
    use super::*;
    #[test]
    fn production_mode_rejects_test_functions_instead_of_stripping_them() {
        let src = include_str!("compiler/fixtures/v1/c175.ko");
        let production = Compiler::new_with_options(CompilerOptions::default());
        let error = production
            .compile_source_with_manifest_and_report(src)
            .expect_err("production mode must reject local test declarations");
        assert!(
            error.contains("E_TEST_ONLY_PRODUCTION"),
            "unexpected error: {error}"
        );
        let test_mode = Compiler::new_with_options(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        });
        let (code, _manifest, report) = test_mode
            .compile_source_with_manifest_and_report(src)
            .expect("compile in test mode");
        let parsed = ProgramMetadata::parse(&code).expect("parse test harness metadata");
        assert_eq!(parsed.metadata.version_minor, 1);
        assert_eq!(parsed.metadata.abi_version, KOTODAMA_ABI_VERSION);
        assert!(
            parsed.contract_interface.is_none(),
            "local test harnesses must use the authenticated generic profile"
        );
        let mut stale_abi = code.clone();
        stale_abi[17] ^= 1;
        assert!(matches!(
            ProgramMetadata::parse(&stale_abi),
            Err(ivm_abi::VMError::ArtifactAbiHashMismatch { .. })
        ));
        assert!(
            report
                .source_map
                .iter()
                .any(|entry| entry.function_name == "smoke")
        );
        assert!(
            report
                .budget_report
                .iter()
                .any(|entry| entry.function_name == "smoke"),
            "a private #[test] function must be an executable root in test mode"
        );
        assert!(
            report
                .budget_report
                .iter()
                .all(|entry| entry.function_name != "helper"),
            "an ordinary unreachable private function must not become a test root"
        );
        let production_code = Compiler::new()
            .compile_source("seiyaku ProductionFixture { view fn inspect() authorize(anyone) {} }")
            .expect("compile production contract");
        let production_metadata =
            ProgramMetadata::parse(&production_code).expect("parse production metadata");
        assert_eq!(production_metadata.metadata.version_minor, 1);
        assert!(
            production_metadata.contract_interface.is_some(),
            "production contracts must retain their CNTR interface"
        );
    }
    #[test]
    fn test_and_production_entrypoints_use_the_same_argument_boundary() {
        let source = "seiyaku Demo { view fn run(int count) authorize(anyone) -> int { return count + 1; } }";
        let mut schemas = Vec::new();
        for mode in [CompilerMode::Test, CompilerMode::Production] {
            let output = Compiler::new_with_options(CompilerOptions {
                mode,
                ..CompilerOptions::default()
            })
            .compile_source_output(source, None)
            .expect("compile public wrapper");
            let run = output
                .contract_interface
                .entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == "run")
                .expect("run descriptor");
            assert!(run.read_keys.is_empty());
            assert!(run.write_keys.is_empty());
            // A pure wrapper emits no ledger-access report in either artifact profile.
            assert_eq!(run.access_hints_complete, None);
            assert!(run.access_hints_skipped.is_empty());
            schemas.push(run.argument_schema.clone().expect("typed argument schema"));
            let parsed = ProgramMetadata::parse(&output.artifact).expect("artifact metadata");
            let syscalls = output.artifact[parsed.code_offset..]
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("instruction word")))
                .filter(|word| {
                    instruction::wide::opcode(*word) == instruction::wide::system::SYSTEM
                })
                .map(encoding::wide::decode_syscallx)
                .collect::<Vec<_>>();
            assert_eq!(
                syscalls
                    .iter()
                    .filter(|number| **number == syscalls::SYSCALL_DECODE_ARGUMENT_RECORD)
                    .count(),
                0,
                "both modes receive the same host-prepared call table"
            );
            for state_access in [
                syscalls::SYSCALL_STATE_GET,
                syscalls::SYSCALL_STATE_SET,
                syscalls::SYSCALL_STATE_DEL,
            ] {
                assert!(
                    !syscalls.contains(&state_access),
                    "pure wrappers must not access test argument state"
                );
            }
        }
        assert_eq!(schemas[0], schemas[1]);
    }
    #[test]
    fn production_rejects_tests_before_resolving_test_only_helpers() {
        let test_only_call_src = include_str!("compiler/fixtures/v1/c176.ko");
        let production = Compiler::new_with_options(CompilerOptions::default());
        let error = production
            .compile_source_with_manifest_and_report(test_only_call_src)
            .expect_err("production rejects tests before resolving their calls");
        assert!(
            error.contains("E_TEST_ONLY_PRODUCTION"),
            "unexpected error: {error}"
        );
        let test_mode = Compiler::new_with_options(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        });
        let error = test_mode
            .compile_source(test_only_call_src)
            .expect_err("test mode must resolve the unknown helper without injection");
        assert!(
            error.contains("unknown function or builtin `require_authority`"),
            "unexpected error: {error}"
        );
    }
    #[test]
    fn test_mode_helpers_emit_private_scallx_syscalls() {
        let src = include_str!("compiler/fixtures/v1/c177.ko");
        let compiler = Compiler::new_with_options(CompilerOptions {
            mode: CompilerMode::Test,
            ..CompilerOptions::default()
        });
        let code = compiler.compile_source(src).expect("compile test helpers");
        let metadata = ProgramMetadata::parse(&code).expect("parse metadata");
        let code_region = &code[metadata.code_offset..];
        for (builtin, syscall) in [
            (
                Builtin::TestActorAccount,
                syscalls::SYSCALL_KOTO_TEST_ACTOR_ACCOUNT,
            ),
            (
                Builtin::TestActorPublicKey,
                syscalls::SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY,
            ),
            (
                Builtin::TestActorSign,
                syscalls::SYSCALL_KOTO_TEST_ACTOR_SIGN,
            ),
            (
                Builtin::TestInvokeEntrypointAs,
                syscalls::SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS,
            ),
            (
                Builtin::TestExpectRejectAs,
                syscalls::SYSCALL_KOTO_TEST_EXPECT_REJECT_AS,
            ),
        ] {
            assert_eq!(builtin.syscall(), Some(syscall), "{builtin:?}");
            let needle = encoding::wide::encode_syscallx(syscall).to_le_bytes();
            assert!(
                code_region
                    .windows(needle.len())
                    .any(|window| window == needle),
                "expected private Kotodama test syscall {syscall:#x} to use SCALLX"
            );
        }
    }
    #[test]
    fn implicit_first_release_prelude_helpers_fail_closed() {
        for (name, call) in [
            (
                "require_authority",
                "require_authority(context::authority())",
            ),
            ("require_owner", "require_owner(context::authority())"),
            ("bps_fee", "bps_fee(10000, 25)"),
            ("checked_add_amount", "checked_add_amount(10, 5)"),
            ("checked_sub_amount", "checked_sub_amount(10, 5)"),
            (
                "require_json_int",
                "require_json_int(Json::parse(\"{}\"), Name::parse(\"value\"))",
            ),
        ] {
            let source = format!(
                "seiyaku Demo {{ permission Probe;  kotoage fn probe() authorize(Probe) {{ let _value = {call}; }} }}"
            );
            let error = Compiler::new()
                .compile_source(&source)
                .expect_err("implicit prelude helper must be unknown");
            assert!(
                error.contains(&format!("unknown function or builtin `{name}`")),
                "unexpected error for {name}: {error}"
            );
        }
    }
    #[test]
    fn decimal_operators_use_extended_nominal_syscalls() {
        let source = include_str!("compiler/fixtures/v1/c178.ko");
        let code = Compiler::new()
            .compile_source(source)
            .expect("compile dynamic decimal operators");
        for syscall in [
            syscalls::SYSCALL_DECIMAL_ADD,
            syscalls::SYSCALL_DECIMAL_MUL,
            syscalls::SYSCALL_DECIMAL_DIV_EXACT,
        ] {
            let encoded = encoding::wide::encode_syscallx(syscall).to_le_bytes();
            assert!(
                code.windows(encoded.len()).any(|window| window == encoded),
                "missing extended decimal syscall {syscall:#x}"
            );
        }
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_typed_query_page_compiles_with_a_structural_public_schema() {
        use ivm_abi::entrypoint::{EntrypointValueTypeNodeV1 as Node, EntrypointValueTypeV1};
        let source = include_str!("compiler/fixtures/v1/c179.ko");
        let artifact = Compiler::new()
            .compile_source(source)
            .expect("compile every typed query-page projection");
        let parsed = ProgramMetadata::parse(&artifact).expect("parse typed query-page metadata");
        let interface = parsed
            .contract_interface
            .as_ref()
            .expect("typed query-page interface");
        assert_eq!(interface.entrypoints.len(), 5);
        let mut encoded_schemas = HashSet::new();
        for (entrypoint_name, view_name) in [
            ("accounts", "AccountView"),
            ("assets", "AssetView"),
            ("asset_definitions", "AssetDefinitionView"),
            ("domains", "DomainView"),
            ("nfts", "NftView"),
        ] {
            let entrypoint = interface
                .entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == entrypoint_name)
                .unwrap_or_else(|| panic!("missing {entrypoint_name} descriptor"));
            let expected_return_type = format!("QueryPage<{view_name}>");
            assert_eq!(
                entrypoint.return_type.as_deref(),
                Some(expected_return_type.as_str())
            );
            let schema = entrypoint
                .return_schema
                .as_ref()
                .unwrap_or_else(|| panic!("missing {entrypoint_name} return schema"));
            let [
                Node::Struct(page),
                Node::List(items),
                Node::Struct(view),
                ..,
            ] = schema.nodes.as_slice()
            else {
                panic!("unexpected {entrypoint_name} schema: {schema:?}");
            };
            assert_eq!(page.name, "kotodama::QueryPage");
            assert_eq!(page.fields, ["items", "next_offset"]);
            assert_eq!(items.capacity, 64);
            assert_eq!(view.name, format!("kotodama::{view_name}"));
            assert!(matches!(
                schema
                    .nodes
                    .as_slice()
                    .get(schema.nodes.len().saturating_sub(2)..),
                Some([
                    Node::Option,
                    Node::Leaf(ivm_abi::entrypoint::EntrypointValueKindV1::Int)
                ])
            ));
            assert!(schema.validate());
            assert_eq!(schema.word_count(), Some(2));
            assert_eq!(
                schema.canonical_type_name().as_deref(),
                Some(expected_return_type.as_str()),
                "artifact verification must see the same structural type name"
            );
            let encoded = norito::to_bytes(schema).expect("encode embedded query-page schema");
            let decoded: EntrypointValueTypeV1 =
                norito::decode_from_bytes(&encoded).expect("decode embedded query-page schema");
            assert_eq!(&decoded, schema);
            assert!(
                encoded_schemas.insert(encoded),
                "{view_name} must retain a distinct structural specialization"
            );
        }
        assert_eq!(encoded_schemas.len(), 5);
        let syscall = encoding::wide::encode_syscallx(syscalls::SYSCALL_CORE_QUERY_PAGE);
        assert_eq!(
            artifact[parsed.code_offset..]
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
                .filter(|word| *word == syscall)
                .count(),
            5,
            "each page entrypoint must lower to exactly one core-query host call"
        );
    }
    #[test]
    fn ordinary_struct_entrypoint_names_come_from_the_exact_abi_schema() {
        let source = include_str!("compiler/fixtures/v1/c180.ko");
        let artifact = Compiler::new()
            .compile_source(source)
            .expect("compile ordinary user-struct entrypoint");
        let parsed = ProgramMetadata::parse(&artifact)
            .expect("admission metadata must parse the compiler-produced artifact");
        let interface = parsed
            .contract_interface
            .as_ref()
            .expect("embedded contract interface");
        let entrypoint = interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "echo")
            .expect("echo entrypoint descriptor");
        let argument_schema = entrypoint
            .argument_schema
            .as_ref()
            .expect("ordinary struct argument schema");
        let field_schema = &argument_schema
            .fields
            .first()
            .expect("one argument-schema field")
            .ty;
        let parameter_type = field_schema
            .canonical_type_name()
            .expect("ordinary struct parameter canonical ABI name");
        assert_eq!(parameter_type, "struct UserStructAbi::Pair");
        assert_eq!(
            entrypoint
                .params
                .first()
                .expect("one entrypoint parameter")
                .type_name,
            parameter_type
        );
        let return_schema = entrypoint
            .return_schema
            .as_ref()
            .expect("ordinary struct return schema");
        let return_type = return_schema
            .canonical_type_name()
            .expect("ordinary struct return canonical ABI name");
        assert_eq!(return_type, "struct UserStructAbi::Pair");
        assert_eq!(
            entrypoint.return_type.as_deref(),
            Some(return_type.as_str())
        );
    }
    #[test]
    fn quantity_div_round_uses_one_extended_nominal_syscall() {
        let source = include_str!("compiler/fixtures/v1/c181.ko");
        let code = Compiler::new()
            .compile_source(source)
            .expect("compile rounded quantity division");
        let encoded = encoding::wide::encode_syscallx(syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND)
            .to_le_bytes();
        assert_eq!(
            code.windows(encoded.len())
                .filter(|window| *window == encoded)
                .count(),
            1,
            "dynamic rounded division must lower to one extended quantity syscall"
        );
    }
    #[test]
    fn manifest_state_descriptors_use_canonical_type_names() {
        let src = include_str!("compiler/fixtures/v1/c182.ko");
        let (_code, manifest) = Compiler::new()
            .compile_source_with_manifest(src)
            .expect("compile state schema");
        let states = manifest.states.expect("state schema");
        assert!(
            states
                .iter()
                .any(|state| state.name == "Counter" && state.type_name == "int")
        );
        assert!(
            states
                .iter()
                .any(|state| state.name == "Prices" && state.type_name == "StateMap<Name, int>")
        );
        assert!(
            states
                .iter()
                .any(|state| { state.name == "MaybeCounter" && state.type_name == "Option<int>" })
        );
        assert!(
            states.iter().any(|state| {
                state.name == "Outcome" && state.type_name == "Result<bool, string>"
            })
        );
    }
    fn wide_durable_state_source(field_count: usize, use_state: bool) -> String {
        let mut source = String::from("seiyaku RuntimeSchemaBoundary {\nstruct Wide {\n");
        for index in 0..field_count {
            source.push_str(&format!("int field_{index};\n"));
        }
        if use_state {
            source.push_str("}\nstate Wide value;\n");
            source.push_str("hajimari() {\nvalue = Wide {\n");
            for index in 0..field_count {
                source.push_str(&format!("field_{index}: 0,\n"));
            }
            source.push_str("};\n}\n");
        } else {
            // StateMap storage has no scalar initialization obligation, so it
            // isolates descriptor validation even when the declared map is
            // otherwise unused by executable code.
            source.push_str("}\nstate StateMap<Name, Wide> value;\n");
        }
        source.push_str("view fn inspect() authorize(anyone) {}\n");
        source.push_str("}\n");
        source
    }
    #[test]
    fn compiler_enforces_the_exact_runtime_state_schema_node_limit() {
        Compiler::new()
            .compile_source(&wide_durable_state_source(
                ivm_abi::state_value::MAX_STATE_VALUE_NODES - 1,
                false,
            ))
            .expect("one struct plus 255 leaves is exactly 256 runtime schema nodes");
        let error = Compiler::new()
            .compile_source(&wide_durable_state_source(
                ivm_abi::state_value::MAX_STATE_VALUE_NODES,
                false,
            ))
            .expect_err("compiler must not emit a 257-node CNTR durable-state schema");
        assert!(
            error.contains(
                "state `value` exceeds the exact V1 runtime StateValueSchema limit of 256 nodes or levels and 65536 encoded bytes"
            ),
            "unexpected compiler error: {error}"
        );
    }
    #[test]
    fn used_state_reports_the_exact_runtime_schema_limit_before_lowering() {
        let error = Compiler::new()
            .compile_source(&wide_durable_state_source(
                ivm_abi::state_value::MAX_STATE_VALUE_NODES,
                true,
            ))
            .expect_err("a used 257-node state schema must fail before IR lowering");
        assert!(
            error.contains(
                "state `value` exceeds the exact V1 runtime StateValueSchema limit of 256 nodes or levels and 65536 encoded bytes"
            ),
            "unexpected compiler error: {error}"
        );
        assert!(
            !error.contains("durable state value is not encodable"),
            "the generic lowering error must not hide the exact CNTR limit: {error}"
        );
    }
    #[test]
    fn lowering_time_abi_schemas_ignore_ambient_norito_flags() {
        let source = include_str!("compiler/fixtures/v1/c183.ko");
        let canonical = {
            let _ambient =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            Compiler::new()
                .compile_source(source)
                .expect("compile with default canonical Norito flags")
        };
        let alternate = {
            let alternate_flags =
                norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            Compiler::new()
                .compile_source(source)
                .expect("compile independently of ambient Norito flags")
        };
        assert_eq!(
            alternate, canonical,
            "ambient Norito flags must not change a deployable artifact"
        );
        let parsed = ProgramMetadata::parse(&canonical).expect("parse canonical artifact");
        let literals = parsed.literal_section.expect("schema literal table");
        let mut norito_payloads = Vec::new();
        for index in 0..literals.count {
            let descriptor_start = index
                .checked_mul(8)
                .and_then(|offset| literals.entries_start.checked_add(offset))
                .expect("literal descriptor offset");
            let descriptor_end = descriptor_start
                .checked_add(8)
                .expect("literal descriptor range");
            let descriptor = u64::from_le_bytes(
                canonical
                    .get(descriptor_start..descriptor_end)
                    .expect("literal descriptor inside artifact")
                    .try_into()
                    .expect("literal descriptor"),
            );
            let (kind, relative_offset) = crate::metadata::decode_literal_descriptor(descriptor)
                .expect("decode literal descriptor");
            if kind != crate::metadata::LiteralKindV1::PointerTlv {
                continue;
            }
            let start = literals
                .start
                .checked_add(usize::try_from(relative_offset).expect("literal offset fits usize"))
                .expect("literal start offset");
            assert!(
                (literals.data_start..literals.data_end).contains(&start),
                "literal start must be inside the validated data range"
            );
            let header_end = start.checked_add(7).expect("pointer TLV header range");
            let header = canonical
                .get(start..header_end)
                .expect("pointer TLV header inside artifact");
            let pointer_type = u16::from_be_bytes(
                header
                    .get(..2)
                    .expect("pointer type id bytes")
                    .try_into()
                    .expect("pointer type id"),
            );
            if pointer_type != PointerType::NoritoBytes as u16 {
                continue;
            }
            let payload_len = usize::try_from(u32::from_be_bytes(
                header
                    .get(3..7)
                    .expect("pointer payload length bytes")
                    .try_into()
                    .expect("pointer payload length"),
            ))
            .expect("pointer payload length fits usize");
            let payload_end = header_end
                .checked_add(payload_len)
                .expect("pointer payload range");
            let envelope_end = payload_end
                .checked_add(iroha_crypto::Hash::LENGTH)
                .expect("pointer hash range");
            assert!(
                envelope_end <= literals.data_end,
                "pointer TLV must fit the validated literal-data range"
            );
            norito_payloads.push(
                canonical
                    .get(header_end..payload_end)
                    .expect("pointer payload inside artifact"),
            );
        }
        assert!(norito_payloads.iter().any(|payload| {
            ivm_abi::codec::decode_canonical_norito::<ivm_abi::state_value::StateValueSchemaV1>(
                payload,
            )
            .is_ok()
        }));
        assert!(
            parsed
                .contract_interface
                .as_ref()
                .unwrap()
                .entrypoints
                .iter()
                .any(|entrypoint| {
                    entrypoint
                        .argument_schema
                        .as_ref()
                        .is_some_and(|schema| schema.validate())
                })
        );
        assert!(norito_payloads.iter().any(|payload| {
            ivm_abi::codec::decode_canonical_norito::<ivm_abi::json::JsonConstructionSchemaV1>(
                payload,
            )
            .is_ok()
        }));
    }
    #[test]
    fn contract_identity_is_preserved_in_artifact_and_manifest() {
        let source = include_str!("compiler/fixtures/v1/c184.ko");
        let (artifact, manifest) = Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile named seiyaku");
        let interface = ProgramMetadata::parse(&artifact)
            .expect("parse contract artifact")
            .contract_interface
            .expect("embedded contract interface");
        assert_eq!(interface.seiyaku_name, "Treasury");
        assert_eq!(manifest.seiyaku_name.as_deref(), Some("Treasury"));
    }
    #[test]
    fn user_facing_type_first_counter_example_compiles_as_a_complete_contract() {
        let source = include_str!("compiler/fixtures/v1/c185.ko");
        let (artifact, manifest) = Compiler::new()
            .compile_source_with_manifest(source)
            .expect("compile the normative type-first Counter example");
        let interface = ProgramMetadata::parse(&artifact)
            .expect("parse Counter artifact")
            .contract_interface
            .expect("Counter embeds its contract interface");
        assert_eq!(interface.seiyaku_name, "Counter");
        assert!(
            interface
                .states
                .iter()
                .any(|state| { state.name == "value" && state.ty == EmbeddedStateType::Int })
        );
        let increment = interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "increment")
            .expect("authorized increment entrypoint");
        assert_eq!(
            increment.authorization,
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "CanIncrement".parse().unwrap()
            )
        );
        assert!(
            interface
                .entrypoints
                .iter()
                .any(|entrypoint| entrypoint.name == "hajimari")
        );
        assert!(
            interface
                .entrypoints
                .iter()
                .any(|entrypoint| entrypoint.name == "current")
        );
        assert_eq!(manifest.seiyaku_name.as_deref(), Some("Counter"));
        assert!(manifest.abi_hash.is_some());
    }
    #[test]
    fn leaf_identity_uses_the_same_bounded_table_frame_as_all_functions() {
        super::local_structural_controls::leaf_identity(include_str!(
            "compiler/fixtures/v1/c186.ko"
        ));
    }
    #[test]
    fn call_local_values_avoid_callee_save_and_spill_stack_traffic() {
        super::local_structural_controls::call_local(include_str!("compiler/fixtures/v1/c187.ko"));
    }
    #[test]
    fn whole_program_dce_removes_unused_private_code_and_extra_dispatch_wrappers() {
        let source = include_str!("compiler/fixtures/v1/c188.ko");
        let (artifact, _manifest, report) = Compiler::new()
            .compile_source_with_manifest_and_report(source)
            .expect("compile whole-program DCE fixture");
        assert!(
            report
                .budget_report
                .iter()
                .all(|function| function.function_name != "unused"),
            "an unreachable private function must have no emitted bytecode"
        );
        assert!(
            report
                .budget_report
                .iter()
                .any(|function| { function.function_name == "helper" })
        );
        assert!(
            report
                .budget_report
                .iter()
                .any(|function| { function.function_name == "exposed" })
        );
        assert_eq!(
            report
                .budget_report
                .iter()
                .filter(|function| function.function_name == "exposed")
                .count(),
            1
        );
        let metadata = ProgramMetadata::parse(&artifact).expect("parse DCE artifact");
        let entrypoint_count = metadata
            .contract_interface
            .as_ref()
            .expect("embedded interface")
            .entrypoints
            .len();
        assert_eq!(entrypoint_count, 1);
        let function_words = report
            .budget_report
            .iter()
            .map(|function| {
                usize::try_from(function.bytecode_words).expect("word count fits usize")
            })
            .sum::<usize>();
        let emitted_words = artifact[metadata.code_offset..].len() / 4;
        assert_eq!(
            emitted_words,
            1 + function_words,
            "code contains only PC-zero HALT and reachable function bodies"
        );
    }
    #[test]
    fn whole_program_dce_preserves_lifecycle_trigger_helpers_and_cntr_targets() {
        let source = include_str!("compiler/fixtures/v1/c189.ko");
        let (artifact, _manifest, report) = Compiler::new()
            .compile_source_with_manifest_and_report(source)
            .expect("compile lifecycle reachability fixture");
        let emitted = report
            .budget_report
            .iter()
            .map(|function| function.function_name.as_str())
            .collect::<BTreeSet<_>>();
        assert!(
            [
                "initialize",
                "improve",
                "handle_trigger",
                "hajimari",
                "kaizen",
                "run",
                "inspect",
            ]
            .into_iter()
            .all(|name| emitted.contains(name)),
            "every helper reachable from a public or lifecycle root must remain: {emitted:?}"
        );
        assert!(
            !emitted.contains("orphan"),
            "a private function outside the executable graph must be removed"
        );
        let metadata = ProgramMetadata::parse(&artifact).expect("parse lifecycle artifact");
        let interface = metadata
            .contract_interface
            .as_ref()
            .expect("embedded lifecycle interface");
        assert_eq!(interface.entrypoints.len(), 4);
        let run = interface
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "run")
            .expect("trigger callback entrypoint");
        assert_eq!(run.triggers.len(), 1);
        for entrypoint in &interface.entrypoints {
            let body = report
                .budget_report
                .iter()
                .find(|function| function.function_name == entrypoint.name)
                .expect("CNTR points to a retained body");
            assert_eq!(entrypoint.entry_pc, body.pc_start);
            assert!(
                interface
                    .callables
                    .iter()
                    .any(|callable| callable.entry_pc == body.pc_start
                        && callable.frame_bytes == body.frame_bytes)
            );
        }
    }
    #[test]
    fn split_spill_cluster_reloads_once_and_reuses_a_real_register() {
        super::local_structural_controls::split_spill(include_str!("compiler/fixtures/v1/c190.ko"));
    }
    #[test]
    fn structured_branches_use_two_words_and_fuse_signed_comparisons() {
        let source = include_str!("compiler/fixtures/v1/c191.ko");
        let (artifact, _manifest, report) = Compiler::new()
            .compile_source_with_manifest_and_report(source)
            .expect("compile branch optimization fixture");
        let metadata = ProgramMetadata::parse(&artifact).expect("parse branch artifact");
        let function_words = |name: &str| {
            let implementation = name.to_owned();
            let budget = report
                .budget_report
                .iter()
                .find(|entry| entry.function_name == implementation)
                .unwrap_or_else(|| panic!("missing budget for {name}"));
            artifact[metadata.code_offset + budget.pc_start as usize
                ..metadata.code_offset + budget.pc_end as usize]
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
                .collect::<Vec<_>>()
        };
        let choose = function_words("choose");
        let branch_index = choose
            .iter()
            .position(|word| {
                matches!(
                    instruction::wide::opcode(*word),
                    instruction::wide::control::BEQ | instruction::wide::control::BNE
                )
            })
            .unwrap_or_else(|| panic!("boolean branch; words={choose:08x?}"));
        assert_eq!(
            instruction::wide::imm8(choose[branch_index]),
            2,
            "the conditional must skip exactly one relaxed transfer"
        );
        assert!(matches!(
            instruction::wide::opcode(choose[branch_index + 1]),
            instruction::wide::control::JAL | instruction::wide::control::JMP
        ));
        let ordered = function_words("ordered");
        assert!(
            ordered.iter().any(|word| {
                instruction::wide::opcode(*word) == instruction::wide::system::SYSTEM
                    && encoding::wide::decode_syscallx(*word) == syscalls::SYSCALL_INT_LT
            }),
            "adaptive int comparison must use the exact INT_LT syscall"
        );
        assert!(
            ordered.iter().all(|word| {
                !matches!(
                    instruction::wide::opcode(*word),
                    instruction::wide::control::BLT | instruction::wide::control::BGE
                ) && instruction::wide::opcode(*word) != instruction::wide::arithmetic::SLT
            }),
            "adaptive int pointers must never be compared by scalar signed opcodes"
        );
        let copied_length = function_words("copied_length");
        let fused_branches = copied_length
            .iter()
            .enumerate()
            .filter(|(_, word)| {
                matches!(
                    instruction::wide::opcode(**word),
                    instruction::wide::control::BLT | instruction::wide::control::BGE
                )
            })
            .collect::<Vec<_>>();
        assert!(
            !fused_branches.is_empty(),
            "the compiler-owned bounded List loop must branch directly on its scalar transport comparison: {copied_length:08x?}"
        );
        for (index, word) in fused_branches {
            assert_eq!(
                instruction::wide::imm8(*word),
                2,
                "the fused conditional must skip exactly one relaxed transfer"
            );
            assert!(matches!(
                copied_length
                    .get(index + 1)
                    .map(|word| instruction::wide::opcode(*word)),
                Some(instruction::wide::control::JAL | instruction::wide::control::JMP)
            ));
        }
        assert!(
            copied_length.iter().all(|word| {
                instruction::wide::opcode(*word) != instruction::wide::arithmetic::SLT
            }),
            "the fused scalar comparison must not also materialize an SLT boolean: {copied_length:08x?}"
        );
    }
    #[test]
    fn compact_branch_layout_splits_merge_heavy_and_backward_edges() {
        let branch = |label, then_bb, else_bb| ir::BasicBlock {
            label: ir::Label(label),
            instrs: Vec::new(),
            terminator: ir::Terminator::Branch {
                cond: ir::Temp(label),
                then_bb: ir::Label(then_bb),
                else_bb: ir::Label(else_bb),
            },
        };
        let terminal = |label| ir::BasicBlock {
            label: ir::Label(label),
            instrs: Vec::new(),
            terminator: ir::Terminator::Return(None),
        };
        let mut function = ir::Function {
            name: "compact".to_owned(),
            params: Vec::new(),
            blocks: vec![
                branch(0, 1, 2),
                branch(1, 3, 4),
                terminal(3),
                terminal(4),
                branch(2, 3, 4),
            ],
            entry: ir::Label(0),
            location: SourceLocation { line: 1, column: 1 },
        };
        super::layout_compact_branch_fallthrough(&mut function)
            .expect("merge-heavy graph has a compact fallthrough layout");
        assert_eq!(function.blocks[0].label, function.entry);
        assert!(
            function.blocks.iter().any(|block| {
                block.label == ir::Label(5)
                    && block.terminator == ir::Terminator::Jump(ir::Label(3))
            }),
            "the late merge branch must receive one unique edge-split block: {function:?}"
        );
        for (index, block) in function.blocks.iter().enumerate() {
            let ir::Terminator::Branch {
                then_bb, else_bb, ..
            } = &block.terminator
            else {
                continue;
            };
            let next = function
                .blocks
                .get(index + 1)
                .expect("a conditional cannot terminate a compact layout")
                .label;
            assert!(next == *then_bb || next == *else_bb, "{function:?}");
        }
        let mut backward_only = ir::Function {
            name: "irreducible".to_owned(),
            params: Vec::new(),
            blocks: vec![
                ir::BasicBlock {
                    label: ir::Label(0),
                    instrs: Vec::new(),
                    terminator: ir::Terminator::Jump(ir::Label(1)),
                },
                branch(1, 0, 0),
            ],
            entry: ir::Label(0),
            location: SourceLocation { line: 1, column: 1 },
        };
        super::layout_compact_branch_fallthrough(&mut backward_only)
            .expect("a backward-only conditional receives an edge-split block");
        assert_eq!(backward_only.blocks.len(), 3);
        let ir::Terminator::Branch { then_bb, .. } = &backward_only.blocks[1].terminator else {
            panic!("expected backward conditional: {backward_only:?}");
        };
        assert_eq!(*then_bb, backward_only.blocks[2].label);
        assert_eq!(
            backward_only.blocks[2].terminator,
            ir::Terminator::Jump(ir::Label(0))
        );
    }
    #[test]
    fn valid_many_diamond_and_bounded_backedge_sources_keep_conditionals_two_words() {
        let mut source = String::from(include_str!("compiler/fixtures/v1/c192.ko"));
        for value in 1..=64 {
            source.push_str(&format!(
                "if flag {{ total = total + {value}; }} else {{ total = total - {value}; }}\n"
            ));
        }
        source.push_str(include_str!("compiler/fixtures/v1/c193.ko"));
        let (artifact, _manifest, report) = Compiler::new()
            .compile_source_with_manifest_and_report(&source)
            .expect("compile merge-heavy diamonds and bounded backedges");
        let metadata = ProgramMetadata::parse(&artifact).expect("parse branch stress artifact");
        for name in ["many_diamonds", "bounded_backedges"] {
            let implementation = name.to_owned();
            let budget = report
                .budget_report
                .iter()
                .find(|entry| entry.function_name == implementation)
                .unwrap_or_else(|| panic!("missing budget report for {name}"));
            let words = artifact[metadata.code_offset + budget.pc_start as usize
                ..metadata.code_offset + budget.pc_end as usize]
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
                .collect::<Vec<_>>();
            let mut conditional_count = 0;
            for (index, word) in words.iter().enumerate() {
                if !matches!(
                    instruction::wide::opcode(*word),
                    instruction::wide::control::BEQ
                        | instruction::wide::control::BNE
                        | instruction::wide::control::BLT
                        | instruction::wide::control::BGE
                        | instruction::wide::control::BLTU
                        | instruction::wide::control::BGEU
                ) {
                    continue;
                }
                conditional_count += 1;
                assert_eq!(
                    instruction::wide::imm8(*word),
                    2,
                    "{name} conditional must skip exactly one transfer: {words:08x?}"
                );
                assert!(matches!(
                    words
                        .get(index + 1)
                        .map(|next| instruction::wide::opcode(*next)),
                    Some(instruction::wide::control::JAL | instruction::wide::control::JMP)
                ));
            }
            assert!(conditional_count > 0, "{name} must retain conditional CFGs");
        }
    }
    #[test]
    fn compile_report_excludes_dead_and_unreachable_instructions() {
        let source = include_str!("compiler/fixtures/v1/c194.ko");
        let (artifact, _manifest, report) = Compiler::new()
            .compile_source_with_manifest_and_report(source)
            .expect("compile dead-code optimization fixture");
        let answer = report
            .budget_report
            .iter()
            .find(|entry| entry.function_name == "answer")
            .expect("answer budget report");
        assert_eq!(answer.frame_bytes, 16);
        let metadata = ProgramMetadata::parse(&artifact).expect("parse dead-code artifact");
        let words = artifact[metadata.code_offset + answer.pc_start as usize
            ..metadata.code_offset + answer.pc_end as usize]
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
            .collect::<Vec<_>>();
        assert_eq!(
            words.iter().filter(|word| instruction::wide::opcode(**word) == instruction::wide::memory::LDLIT).count(), 1,
            "only the returned value literal survives; report={answer:?}; words={words:08x?}"
        );
    }
    #[test]
    fn compile_report_sidecars_are_hash_bound_and_preserve_locations() {
        let source = include_str!("compiler/fixtures/v1/c195.ko");
        let (_artifact, _manifest, mut report) = Compiler::new()
            .compile_source_with_manifest_and_report(source)
            .expect("compile sidecar fixture");
        let source_file = crate::source::SourceFile::new(
            crate::source::SourceId(0),
            "contracts/sidecar.ko",
            source,
        );
        let mut exact_segments = 0_usize;
        for entry in &mut report.source_map {
            entry.source.source_path = Some("contracts/sidecar.ko".to_owned());
            if entry.source.byte_start < entry.source.byte_end {
                exact_segments += 1;
                let start = usize::try_from(entry.source.byte_start).expect("source offset");
                let end = usize::try_from(entry.source.byte_end).expect("source offset");
                assert!(start < end && end <= source.len());
                assert!(source.is_char_boundary(start) && source.is_char_boundary(end));
                let expected = source_file.line_column(entry.source.byte_start);
                assert_eq!(entry.source.line, u32::try_from(expected.line).unwrap());
                assert_eq!(entry.source.column, u32::try_from(expected.column).unwrap());
            }
        }
        assert_eq!(
            exact_segments, 1,
            "source metadata is retained once per emitted function without MIR marker instructions"
        );
        for entry in &mut report.budget_report {
            entry.source.as_mut().expect("budget source").source_path =
                Some("contracts/sidecar.ko".to_owned());
        }
        let source_map = json::parse_value(
            &report
                .render_source_map_json()
                .expect("render source-map sidecar"),
        )
        .expect("parse source-map sidecar");
        let budget =
            json::parse_value(&report.render_budget_json().expect("render budget sidecar"))
                .expect("parse budget sidecar");
        assert_eq!(source_map["sidecar_version"].as_u64(), Some(1));
        assert_eq!(source_map["kind"].as_str(), Some("source-map"));
        assert_eq!(
            source_map["artifact_hash"].as_str(),
            Some(report.artifact_hash.to_string().as_str())
        );
        assert_eq!(
            source_map["entries"][0]["source_path"].as_str(),
            Some("contracts/sidecar.ko")
        );
        assert_eq!(budget["kind"].as_str(), Some("budget"));
        assert_eq!(
            budget["artifact_hash"].as_str(),
            Some(report.artifact_hash.to_string().as_str())
        );
        assert_eq!(
            budget["entries"][0]["source_path"].as_str(),
            Some("contracts/sidecar.ko")
        );
        assert!(budget["entries"][0]["line"].as_u64().is_some());
    }
    #[test]
    fn legacy_source_facade_cannot_bypass_canonical_resolution_audits() {
        let source = include_str!("compiler/fixtures/v1/c196.ko");
        let compiler = Compiler::new();
        let diagnostics = crate::session::CompilerSession::new(compiler.opts.clone())
            .build(crate::session::CompileRequest {
                source,
                source_name: None,
            })
            .expect_err("a parameter must not shadow a seiyaku constant");
        assert_eq!(diagnostics.diagnostics.len(), 1);
        let diagnostic = &diagnostics.diagnostics[0];
        assert_eq!(diagnostic.code, "E_LOCAL_SHADOWING");
        assert_eq!(
            diagnostic.phase,
            crate::diagnostic::DiagnosticPhase::Resolve
        );
        assert_eq!(
            diagnostic.message,
            "local binding `limit` shadows a const declaration"
        );
        let error = compiler
            .compile_source(source)
            .expect_err("a parameter must not shadow a seiyaku constant");
        assert_eq!(
            error,
            diagnostics.render_human(),
            "the convenience facade must preserve the canonical structured diagnostic"
        );
    }
}
impl Compiler {
    /// Create a new compiler instance.
    pub fn new() -> Self {
        let lang = i18n::detect_language();
        Self {
            lang,
            opts: CompilerOptions::default(),
        }
    }
    /// Create a new compiler using a specific language.
    pub fn new_with_language(lang: Language) -> Self {
        Self {
            lang,
            opts: CompilerOptions::default(),
        }
    }
    /// Create a new compiler with custom options.
    pub fn new_with_options(opts: CompilerOptions) -> Self {
        let lang = i18n::detect_language();
        Self { lang, opts }
    }
    /// Compile a KOTODAMA source file into IVM bytecode.
    pub fn compile_file<P: std::convert::AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<Vec<u8>, String> {
        let path = path.as_ref();
        let root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let loaded =
            crate::driver::load_source_project(path, root, &std::collections::BTreeMap::new())
                .map_err(|error| error.to_string())?;
        let crate::driver::LoadedProjectGraph::Source(graph) = loaded.graph else {
            unreachable!("source loader returns a source graph")
        };
        let source_name = graph.root.source_name.clone();
        crate::driver::BuildDriver::new(
            crate::session::CompilerSession::new(self.opts.clone()),
            COMPILER_FINGERPRINT,
        )
        .compile_project(graph, &source_name)
        .map(|output| output.artifact)
        .map_err(|error| error.to_string())
    }
    /// Compile a KOTODAMA source string into IVM bytecode.
    pub fn compile_source(&self, src: &str) -> Result<Vec<u8>, String> {
        self.compile_source_output(src, None)
            .map(|output| output.artifact)
    }
    /// Run every source compilation through the canonical spanned session.
    ///
    /// Keeping this adapter inside the legacy facade prevents SDK and test
    /// callers from accidentally bypassing CST recovery, resolution audits,
    /// production-mode gates, or structured diagnostics.
    fn compile_source_output(
        &self,
        src: &str,
        source_name: Option<&str>,
    ) -> Result<crate::session::CompileOutput, String> {
        crate::session::CompilerSession::new(self.opts.clone())
            .build(crate::session::CompileRequest {
                source: src,
                source_name,
            })
            .map_err(|diagnostics| diagnostics.render_human())
    }
    fn lower_typed_program(
        &self,
        typed: TypedProgram,
        source_name: Option<&str>,
    ) -> Result<LoweredCompilation, DiagnosticBundle> {
        if self.opts.max_cycles == 0 {
            return Err(native_diagnostic_bundle(
                "K4001",
                DiagnosticPhase::Artifact,
                source_name,
                None,
                "the selected max_cycles ceiling must be greater than zero".to_owned(),
            ));
        }
        if typed.unit.kind != SourceUnitKind::Seiyaku {
            return Err(native_diagnostic_bundle(
                "K4003",
                DiagnosticPhase::Artifact,
                source_name,
                None,
                "a reusable module cannot be emitted as a deployable .to artifact".to_owned(),
            ));
        }
        if self.opts.mode == CompilerMode::Production && typed.test_support_enabled {
            let location = typed.items.iter().find_map(|item| match item {
                TypedItem::Function(function) if function.modifiers.is_test => {
                    Some(function.location)
                }
                _ => None,
            });
            return Err(native_diagnostic_bundle(
                "E_TEST_ONLY_PRODUCTION",
                DiagnosticPhase::Semantic,
                source_name,
                location,
                "typed HIR analyzed with local test capabilities cannot be emitted in production mode"
                    .to_owned(),
            ));
        }
        semantic::validate_linked_program(&typed, self.opts.force_zk).map_err(|error| {
            DiagnosticBundle::single(Diagnostic::error(
                error.code,
                DiagnosticPhase::Semantic,
                error.message,
                source_span(source_name, None),
            ))
        })?;
        if let Err(violations) = policy::enforce_on_chain_profile(&typed) {
            let diagnostics = violations
                .into_iter()
                .map(|error| {
                    Diagnostic::error(
                        "K2100",
                        DiagnosticPhase::Semantic,
                        error.message,
                        source_span(source_name, None),
                    )
                })
                .collect();
            return Err(DiagnosticBundle::new(diagnostics));
        }
        // Validate features supported by the current code generator.
        validate_codegen_supported(&typed)
            .map_err(|failures| lowering_diagnostic_bundle("K3001", failures, source_name))?;
        let state_descriptors = build_state_descriptors(&typed).map_err(|message| {
            native_diagnostic_bundle(
                "K3099",
                DiagnosticPhase::Lowering,
                source_name,
                None,
                message,
            )
        })?;
        let ir_program =
            ir::lower_with_cap_diagnostics(&typed, usize::from(COLLECTION_ITERATION_CAP))
                .map_err(|failures| lowering_diagnostic_bundle("K3003", failures, source_name))?;
        let executable_roots = executable_ir_roots(&typed, self.opts.mode == CompilerMode::Test);
        Ok(LoweredCompilation {
            typed,
            state_descriptors,
            ir_program,
            executable_roots,
            source_name: source_name.map(ToOwned::to_owned),
        })
    }
    fn construct_ssa_program(
        &self,
        lowered: LoweredCompilation,
    ) -> Result<SsaCompilation, DiagnosticBundle> {
        let LoweredCompilation {
            typed,
            state_descriptors,
            ir_program,
            executable_roots,
            source_name,
        } = lowered;
        let ssa_program = crate::ssa::Program::from_ir(ir_program).map_err(|message| {
            native_diagnostic_bundle(
                "K3005",
                DiagnosticPhase::Lowering,
                source_name.as_deref(),
                None,
                message,
            )
        })?;
        Ok(SsaCompilation {
            typed,
            state_descriptors,
            ssa_program,
            executable_roots,
            source_name,
        })
    }
    fn optimize_ssa_program(
        &self,
        ssa: SsaCompilation,
    ) -> Result<PreparedCompilation, DiagnosticBundle> {
        let SsaCompilation {
            typed,
            state_descriptors,
            mut ssa_program,
            executable_roots,
            source_name,
        } = ssa;
        ssa_program
            .optimize_and_retain(&executable_roots, &private_literal_candidates(&typed))
            .map_err(|message| {
                native_diagnostic_bundle(
                    "K3004",
                    DiagnosticPhase::Lowering,
                    source_name.as_deref(),
                    None,
                    message,
                )
            })?;
        ssa_program
            .inline_single_use_private_calls(&executable_roots, &private_inline_candidates(&typed))
            .map_err(|message| {
                native_diagnostic_bundle(
                    "K3004",
                    DiagnosticPhase::Lowering,
                    source_name.as_deref(),
                    None,
                    message,
                )
            })?;
        Ok(PreparedCompilation {
            typed,
            state_descriptors,
            ssa_program,
            source_name,
        })
    }
    fn destroy_ssa_program(
        &self,
        prepared: PreparedCompilation,
    ) -> Result<CodegenCompilation, DiagnosticBundle> {
        let PreparedCompilation {
            typed,
            state_descriptors,
            ssa_program,
            source_name,
        } = prepared;
        let ir_program = ssa_program.into_ir().map_err(|message| {
            native_diagnostic_bundle(
                "K3006",
                DiagnosticPhase::Lowering,
                source_name.as_deref(),
                None,
                message,
            )
        })?;
        Ok(CodegenCompilation {
            typed,
            state_descriptors,
            ir_program,
            source_name,
        })
    }
    fn compile_codegen(
        &self,
        prepared: CodegenCompilation,
    ) -> Result<CompilationArtifacts, String> {
        let CodegenCompilation {
            typed,
            state_descriptors,
            ir_program: mut ir_prog,
            source_name,
        } = prepared;
        if ir_prog.functions.is_empty() {
            return Err(i18n::translate(self.lang, Message::NoFunctions));
        }
        let statement_sources = statement_sources::Sources::take(&mut ir_prog, &typed);
        let mut statement_seeds = Vec::new();
        for function in &mut ir_prog.functions {
            layout_compact_branch_fallthrough(function)?;
        }
        // Stage 1 pointer‑ABI: collect string constants and integer constants used by ops.
        use std::collections::{HashMap, HashSet};
        let mut string_map: HashMap<(usize, ir::Temp), String> = HashMap::new();
        let mut datarefs: Vec<(ir::DataRefKind, String)> = Vec::new();
        let mut int_const_map: HashMap<(usize, ir::Temp), i64> = HashMap::new();
        let mut param_temp_map: HashMap<(usize, usize), ir::Temp> = HashMap::new();
        let mut string_literal_temps: HashSet<(usize, ir::Temp)> = HashSet::new();
        let mut dataref_kind_map: HashMap<(usize, ir::Temp), ir::DataRefKind> = HashMap::new();
        let mut state_path_hints: HashMap<(usize, ir::Temp), StatePathHint> = HashMap::new();
        let mut norito_literal_map: HashMap<(usize, ir::Temp), String> = HashMap::new();
        let mut instruction_literal_access_map: HashMap<(usize, ir::Temp), AccessSets> =
            HashMap::new();
        let multiply_defined_dests = multiply_defined_temps(&ir_prog);
        let map_key_encodings = ir_prog
            .functions
            .iter()
            .enumerate()
            .flat_map(|(index, function)| {
                function.blocks.iter().flat_map(move |block| {
                    block
                        .instrs
                        .iter()
                        .filter_map(move |instruction| match instruction {
                            ir::Instr::PathMapKeyNorito { key_blob, .. } => {
                                Some((index, *key_blob))
                            }
                            _ => None,
                        })
                })
            })
            .collect::<HashSet<_>>();
        let mut authority_account_temps: HashSet<(usize, ir::Temp)> = HashSet::new();
        let func_count = ir_prog.functions.len();
        let mut access_sets: Vec<AccessSets> = vec![AccessSets::default(); func_count];
        let mut hint_skips: Vec<IndexSet<String>> = vec![IndexSet::new(); func_count];
        let mut hint_diagnostics = AccessHintDiagnostics::default();
        use super::ir::DataRefKind as DRK;
        for (func_idx, func) in ir_prog.functions.iter().enumerate() {
            for bb in &func.blocks {
                for instr in &bb.instrs {
                    if let ir::Instr::Binary { dest, .. } = instr {
                        // Temps are mutable in loop lowerings (e.g., `i = i + 1`), so
                        // stale const facts must be dropped before codegen-time folding.
                        int_const_map.remove(&(func_idx, *dest));
                        authority_account_temps.remove(&(func_idx, *dest));
                        instruction_literal_access_map.remove(&(func_idx, *dest));
                    }
                    if let ir::Instr::Copy { dest, src } = instr {
                        if dest != src {
                            let dest_key = (func_idx, *dest);
                            string_map.remove(&dest_key);
                            dataref_kind_map.remove(&dest_key);
                            state_path_hints.remove(&dest_key);
                            int_const_map.remove(&dest_key);
                            norito_literal_map.remove(&dest_key);
                            instruction_literal_access_map.remove(&dest_key);
                            string_literal_temps.remove(&dest_key);
                            authority_account_temps.remove(&dest_key);
                            if !multiply_defined_dests.contains(&dest_key) {
                                if let Some(val) = string_map.get(&(func_idx, *src)).cloned() {
                                    string_map.insert(dest_key, val);
                                }
                                if let Some(kind) = dataref_kind_map.get(&(func_idx, *src)).copied()
                                {
                                    dataref_kind_map.insert(dest_key, kind);
                                }
                                if let Some(hint) = state_path_hints.get(&(func_idx, *src)).cloned()
                                {
                                    state_path_hints.insert(dest_key, hint);
                                }
                                if let Some(val) = int_const_map.get(&(func_idx, *src)).copied() {
                                    int_const_map.insert(dest_key, val);
                                }
                                if let Some(val) =
                                    norito_literal_map.get(&(func_idx, *src)).cloned()
                                {
                                    norito_literal_map.insert(dest_key, val);
                                }
                                if let Some(access) = instruction_literal_access_map
                                    .get(&(func_idx, *src))
                                    .cloned()
                                {
                                    instruction_literal_access_map.insert(dest_key, access);
                                }
                                if string_literal_temps.contains(&(func_idx, *src)) {
                                    string_literal_temps.insert(dest_key);
                                }
                                if authority_account_temps.contains(&(func_idx, *src)) {
                                    authority_account_temps.insert(dest_key);
                                }
                            }
                        }
                        continue;
                    }
                    if let ir::Instr::StringConst { dest, value } = instr {
                        string_map.insert((func_idx, *dest), value.clone());
                        string_literal_temps.insert((func_idx, *dest));
                        dataref_kind_map.insert((func_idx, *dest), DRK::Blob);
                    }
                    if let ir::Instr::PointerFromString { dest, kind, src } = instr
                        && let Some(s) = string_map.get(&(func_idx, *src)).cloned()
                    {
                        string_map.insert((func_idx, *dest), s);
                        dataref_kind_map.insert((func_idx, *dest), *kind);
                    }
                    if let ir::Instr::Const { dest, value } = instr {
                        int_const_map.insert((func_idx, *dest), *value);
                    }
                    if let ir::Instr::Unary {
                        dest,
                        op: UnaryOp::Neg,
                        operand,
                    } = instr
                        && let Some(value) = int_const_map.get(&(func_idx, *operand)).copied()
                        && let Some(neg) = value.checked_neg()
                    {
                        int_const_map.insert((func_idx, *dest), neg);
                    }
                    if let ir::Instr::IntFromI64 { dest, .. } | ir::Instr::IntFromU64 { dest, .. } =
                        instr
                    {
                        dataref_kind_map.insert((func_idx, *dest), DRK::Int);
                    }
                    if let ir::Instr::NumericConvert {
                        dest,
                        value,
                        source,
                        destination,
                    } = instr
                    {
                        let source_kind = match source {
                            ir::WideNumericKind::Int => DRK::Int,
                            ir::WideNumericKind::Decimal => DRK::Decimal,
                            ir::WideNumericKind::Quantity => DRK::Quantity,
                        };
                        let destination_kind = match destination {
                            ir::WideNumericKind::Int => DRK::Int,
                            ir::WideNumericKind::Decimal => DRK::Decimal,
                            ir::WideNumericKind::Quantity => DRK::Quantity,
                        };
                        if dataref_kind_map.get(&(func_idx, *value)) == Some(&source_kind)
                            && let Some(raw) = string_map.get(&(func_idx, *value)).cloned()
                        {
                            string_map.insert((func_idx, *dest), raw);
                        }
                        dataref_kind_map.insert((func_idx, *dest), destination_kind);
                    }
                    if let ir::Instr::NumericTryConvert {
                        dest, destination, ..
                    } = instr
                    {
                        dataref_kind_map.insert(
                            (func_idx, *dest),
                            match destination {
                                ir::WideNumericKind::Int => DRK::Int,
                                ir::WideNumericKind::Decimal => DRK::Decimal,
                                ir::WideNumericKind::Quantity => DRK::Quantity,
                            },
                        );
                    }
                    if let ir::Instr::NumericBinary {
                        dest, result_kind, ..
                    } = instr
                    {
                        dataref_kind_map.insert(
                            (func_idx, *dest),
                            match result_kind {
                                ir::WideNumericKind::Int => DRK::Int,
                                ir::WideNumericKind::Decimal => DRK::Decimal,
                                ir::WideNumericKind::Quantity => DRK::Quantity,
                            },
                        );
                    }
                    if let ir::Instr::NumericRound {
                        dest, result_kind, ..
                    } = instr
                    {
                        dataref_kind_map.insert(
                            (func_idx, *dest),
                            match result_kind {
                                ir::WideNumericKind::Int => DRK::Int,
                                ir::WideNumericKind::Decimal => DRK::Decimal,
                                ir::WideNumericKind::Quantity => DRK::Quantity,
                            },
                        );
                    }
                    if let ir::Instr::DecimalToInt { dest, .. } = instr {
                        dataref_kind_map.insert((func_idx, *dest), DRK::Int);
                    }
                    if let ir::Instr::NumericNeg { dest, kind, .. } = instr {
                        dataref_kind_map.insert(
                            (func_idx, *dest),
                            match kind {
                                ir::WideNumericKind::Int => DRK::Int,
                                ir::WideNumericKind::Decimal => DRK::Decimal,
                                ir::WideNumericKind::Quantity => DRK::Quantity,
                            },
                        );
                    }
                    if let ir::Instr::WrappingBinary { dest, .. }
                    | ir::Instr::WrappingNeg { dest, .. } = instr
                    {
                        dataref_kind_map.insert((func_idx, *dest), DRK::Int);
                    }
                    if let ir::Instr::DataRef { dest, kind, value } = instr {
                        // Track typed refs in string_map keyed by temp; kind is handled at use sites
                        string_map.insert((func_idx, *dest), value.clone());
                        datarefs.push((*kind, value.clone()));
                        dataref_kind_map.insert((func_idx, *dest), *kind);
                        match kind {
                            DRK::Name => {
                                state_path_hints.insert(
                                    (func_idx, *dest),
                                    StatePathHint::NameBase(value.clone()),
                                );
                            }
                            DRK::NoritoBytes => {
                                if let Some(path) = state_path_from_norito_literal(value) {
                                    state_path_hints
                                        .insert((func_idx, *dest), StatePathHint::Path(path));
                                }
                            }
                            _ => {}
                        }
                    }
                    if let ir::Instr::PointerFromNorito { dest, kind, .. } = instr {
                        dataref_kind_map.insert((func_idx, *dest), *kind);
                    }
                    if let ir::Instr::PointerToNorito { dest, value } = instr {
                        dataref_kind_map.insert((func_idx, *dest), DRK::NoritoBytes);
                        let literal_kind = dataref_kind_map.get(&(func_idx, *value)).copied();
                        let literal_raw = string_map.get(&(func_idx, *value)).cloned();
                        if let (Some(kind), Some(raw)) = (literal_kind, literal_raw)
                            && let Some(tlv_bytes) = encode_pointer_tlv_bytes(
                                kind,
                                &raw,
                                string_literal_temps.contains(&(func_idx, *value)),
                            )
                        {
                            let hex = hex::encode(tlv_bytes);
                            string_map.insert((func_idx, *dest), format!("0x{hex}"));
                        }
                    }
                    if let ir::Instr::BuildSubmitBallotInline {
                        dest,
                        election_id,
                        ciphertext,
                        nullifier,
                        backend,
                        proof,
                        vk,
                    } = instr
                        && let Some(raw) = submit_ballot_inline_instruction_literal(
                            &string_map,
                            func_idx,
                            *election_id,
                            *ciphertext,
                            *nullifier,
                            *backend,
                            *proof,
                            *vk,
                        )
                    {
                        if let Some(access) = access_for_instruction_literal(&raw) {
                            instruction_literal_access_map.insert((func_idx, *dest), access);
                        }
                        string_map.insert((func_idx, *dest), raw);
                        dataref_kind_map.insert((func_idx, *dest), DRK::NoritoBytes);
                    }
                    if let ir::Instr::ActorAccount { dest, .. } = instr {
                        dataref_kind_map.insert((func_idx, *dest), DRK::Account);
                    }
                    if let ir::Instr::GetAuthority { dest } | ir::Instr::SysvarAuthority { dest } =
                        instr
                    {
                        dataref_kind_map.insert((func_idx, *dest), DRK::Account);
                        authority_account_temps.insert((func_idx, *dest));
                    }
                    if let ir::Instr::ActorPublicKey { dest, .. }
                    | ir::Instr::ActorSign { dest, .. } = instr
                    {
                        dataref_kind_map.insert((func_idx, *dest), DRK::Blob);
                    }
                    if let ir::Instr::LoadVar { dest, name } = instr
                        && let Some(param_idx) = func.params.iter().position(|p| p == name)
                    {
                        param_temp_map.entry((func_idx, param_idx)).or_insert(*dest);
                    }
                    if let ir::Instr::StatePathFromName { dest, name } = instr {
                        dataref_kind_map.insert((func_idx, *dest), DRK::NoritoBytes);
                        if let Some(StatePathHint::NameBase(base)) =
                            state_path_hints.get(&(func_idx, *name))
                        {
                            state_path_hints
                                .insert((func_idx, *dest), StatePathHint::Path(base.clone()));
                        }
                    }
                    if let ir::Instr::StateValueEncode {
                        dest,
                        schema,
                        words,
                    } = instr
                        && let Some(raw) = literal_state_value_record(
                            func_idx,
                            *schema,
                            words,
                            &string_map,
                            &dataref_kind_map,
                            &int_const_map,
                            &string_literal_temps,
                        )
                    {
                        norito_literal_map.insert((func_idx, *dest), raw);
                    }
                    if let ir::Instr::PathMapKeyNorito {
                        dest,
                        base,
                        key_blob,
                    } = instr
                    {
                        dataref_kind_map.insert((func_idx, *dest), DRK::NoritoBytes);
                        if let Some(map_base) = state_path_hints
                            .get(&(func_idx, *base))
                            .and_then(StatePathHint::name_base)
                            .map(str::to_owned)
                        {
                            let literal_path = string_map
                                .get(&(func_idx, *key_blob))
                                .and_then(|raw| {
                                    dataref_kind_map
                                        .get(&(func_idx, *key_blob))
                                        .filter(|kind| matches!(**kind, DRK::NoritoBytes))
                                        .and_then(|_| state_path_for_norito_key(&map_base, raw))
                                })
                                .or_else(|| {
                                    norito_literal_map
                                        .get(&(func_idx, *key_blob))
                                        .and_then(|raw| state_path_for_norito_key(&map_base, raw))
                                });
                            if let Some(path) = literal_path {
                                state_path_hints
                                    .insert((func_idx, *dest), StatePathHint::Path(path));
                            } else {
                                state_path_hints
                                    .insert((func_idx, *dest), StatePathHint::DynamicMapChild);
                            }
                        }
                    }
                    regalloc::visit_instr_defs(instr, |dest| {
                        let key = (func_idx, dest);
                        if multiply_defined_dests.contains(&key) {
                            string_map.remove(&key);
                            dataref_kind_map.remove(&key);
                            state_path_hints.remove(&key);
                            int_const_map.remove(&key);
                            norito_literal_map.remove(&key);
                            instruction_literal_access_map.remove(&key);
                            string_literal_temps.remove(&key);
                            authority_account_temps.remove(&key);
                        }
                    });
                }
            }
        }
        propagate_function_return_literal_facts(
            &ir_prog,
            &mut string_map,
            &mut dataref_kind_map,
            &mut string_literal_temps,
            &multiply_defined_dests,
        );
        // Propagate string literals across call boundaries so callee parameters inherit literal metadata
        // only when every call site agrees on the same literal value.
        let mut fn_index_by_name: HashMap<&str, usize> = HashMap::new();
        for (idx, func) in ir_prog.functions.iter().enumerate() {
            fn_index_by_name.insert(&func.name, idx);
        }
        // Interprocedural facts are valid only when every call site agrees.
        // Remember negative observations as well as positive ones so source
        // order cannot let a later literal or authority value hide an earlier
        // dynamic argument.
        let mut literal_param_conflicts: HashSet<(usize, ir::Temp)> = HashSet::new();
        let mut authority_param_seen: HashSet<(usize, ir::Temp)> = HashSet::new();
        let mut authority_param_conflicts: HashSet<(usize, ir::Temp)> = HashSet::new();
        let mut instruction_param_unknowns: HashSet<(usize, ir::Temp)> = HashSet::new();
        let mut state_path_param_unknowns: HashSet<(usize, ir::Temp)> = HashSet::new();
        for (caller_idx, func) in ir_prog.functions.iter().enumerate() {
            for bb in &func.blocks {
                for instr in &bb.instrs {
                    if let Some((name, args)) = match instr {
                        ir::Instr::Call { callee, args, .. }
                        | ir::Instr::CallMulti { callee, args, .. } => {
                            Some((callee.as_str(), args.as_slice()))
                        }
                        _ => None,
                    } && let Some(&callee_idx) = fn_index_by_name.get(name)
                    {
                        let callee = &ir_prog.functions[callee_idx];
                        let count = usize::min(args.len(), callee.params.len());
                        for (i, &arg_temp) in args.iter().take(count).enumerate() {
                            let Some(&param_temp) = param_temp_map.get(&(callee_idx, i)) else {
                                continue;
                            };
                            let param_key = (callee_idx, param_temp);
                            if !state_path_param_unknowns.contains(&param_key) {
                                if let Some(hint) =
                                    state_path_hints.get(&(caller_idx, arg_temp)).cloned()
                                {
                                    match state_path_hints.get(&param_key) {
                                        Some(existing) if existing != &hint => {
                                            state_path_hints.remove(&param_key);
                                            state_path_param_unknowns.insert(param_key);
                                        }
                                        Some(_) => {}
                                        None => {
                                            state_path_hints.insert(param_key, hint);
                                        }
                                    }
                                } else {
                                    state_path_hints.remove(&param_key);
                                    state_path_param_unknowns.insert(param_key);
                                }
                            }
                            if !instruction_param_unknowns.contains(&param_key) {
                                if let Some(access) = instruction_literal_access_map
                                    .get(&(caller_idx, arg_temp))
                                    .cloned()
                                {
                                    instruction_literal_access_map
                                        .entry(param_key)
                                        .or_default()
                                        .union_with(&access);
                                } else {
                                    instruction_literal_access_map.remove(&param_key);
                                    instruction_param_unknowns.insert(param_key);
                                }
                            }
                            let arg_has_authority =
                                authority_account_temps.contains(&(caller_idx, arg_temp));
                            let authority_seen_before = !authority_param_seen.insert(param_key);
                            if !authority_param_conflicts.contains(&param_key) {
                                if !authority_seen_before {
                                    if arg_has_authority {
                                        authority_account_temps.insert(param_key);
                                        dataref_kind_map.insert(param_key, DRK::Account);
                                    } else {
                                        authority_account_temps.remove(&param_key);
                                    }
                                } else if authority_account_temps.contains(&param_key)
                                    != arg_has_authority
                                {
                                    authority_account_temps.remove(&param_key);
                                    authority_param_conflicts.insert(param_key);
                                }
                            }
                            if literal_param_conflicts.contains(&param_key) {
                                continue;
                            }
                            let arg_has_literal = string_literal_temps
                                .contains(&(caller_idx, arg_temp))
                                || dataref_kind_map.contains_key(&(caller_idx, arg_temp));
                            let Some(value) = string_map.get(&(caller_idx, arg_temp)).cloned()
                            else {
                                string_map.remove(&param_key);
                                string_literal_temps.remove(&param_key);
                                dataref_kind_map.remove(&param_key);
                                literal_param_conflicts.insert(param_key);
                                continue;
                            };
                            if !arg_has_literal {
                                string_map.remove(&param_key);
                                string_literal_temps.remove(&param_key);
                                dataref_kind_map.remove(&param_key);
                                literal_param_conflicts.insert(param_key);
                                continue;
                            }
                            if let Some(existing) = string_map.get(&param_key) {
                                if existing != &value {
                                    string_map.remove(&param_key);
                                    string_literal_temps.remove(&param_key);
                                    dataref_kind_map.remove(&param_key);
                                    literal_param_conflicts.insert(param_key);
                                    continue;
                                }
                            } else {
                                string_map.insert(param_key, value);
                            }
                            if string_literal_temps.contains(&(caller_idx, arg_temp)) {
                                string_literal_temps.insert(param_key);
                            }
                            if let Some(kind) =
                                dataref_kind_map.get(&(caller_idx, arg_temp)).copied()
                            {
                                dataref_kind_map.insert(param_key, kind);
                            }
                        }
                    }
                }
            }
        }
        propagate_function_return_literal_facts(
            &ir_prog,
            &mut string_map,
            &mut dataref_kind_map,
            &mut string_literal_temps,
            &multiply_defined_dests,
        );
        for (func_idx, func) in ir_prog.functions.iter().enumerate() {
            for bb in &func.blocks {
                for instr in &bb.instrs {
                    if let ir::Instr::StatePathFromName { dest, name } = instr {
                        dataref_kind_map.insert((func_idx, *dest), DRK::NoritoBytes);
                        if let Some(StatePathHint::NameBase(base)) =
                            state_path_hints.get(&(func_idx, *name))
                        {
                            state_path_hints
                                .insert((func_idx, *dest), StatePathHint::Path(base.clone()));
                        }
                    }
                    if let ir::Instr::PointerToNorito { dest, value } = instr {
                        dataref_kind_map.insert((func_idx, *dest), DRK::NoritoBytes);
                        let literal_kind = dataref_kind_map.get(&(func_idx, *value)).copied();
                        let literal_raw = string_map.get(&(func_idx, *value)).cloned();
                        if let (Some(kind), Some(raw)) = (literal_kind, literal_raw)
                            && let Some(tlv_bytes) = encode_pointer_tlv_bytes(
                                kind,
                                &raw,
                                string_literal_temps.contains(&(func_idx, *value)),
                            )
                        {
                            let hex = hex::encode(tlv_bytes);
                            string_map.insert((func_idx, *dest), format!("0x{hex}"));
                        }
                    }
                    if let ir::Instr::StateValueEncode {
                        dest,
                        schema,
                        words,
                    } = instr
                        && let Some(raw) = literal_state_value_record(
                            func_idx,
                            *schema,
                            words,
                            &string_map,
                            &dataref_kind_map,
                            &int_const_map,
                            &string_literal_temps,
                        )
                    {
                        norito_literal_map.insert((func_idx, *dest), raw);
                    }
                    if let ir::Instr::PathMapKeyNorito {
                        dest,
                        base,
                        key_blob,
                    } = instr
                    {
                        dataref_kind_map.insert((func_idx, *dest), DRK::NoritoBytes);
                        if let Some(map_base) = state_path_hints
                            .get(&(func_idx, *base))
                            .and_then(StatePathHint::name_base)
                            .map(str::to_owned)
                        {
                            let literal_path = string_map
                                .get(&(func_idx, *key_blob))
                                .and_then(|raw| {
                                    dataref_kind_map
                                        .get(&(func_idx, *key_blob))
                                        .filter(|kind| matches!(**kind, DRK::NoritoBytes))
                                        .and_then(|_| state_path_for_norito_key(&map_base, raw))
                                })
                                .or_else(|| {
                                    norito_literal_map
                                        .get(&(func_idx, *key_blob))
                                        .and_then(|raw| state_path_for_norito_key(&map_base, raw))
                                });
                            if let Some(path) = literal_path {
                                state_path_hints
                                    .insert((func_idx, *dest), StatePathHint::Path(path));
                            } else {
                                state_path_hints
                                    .insert((func_idx, *dest), StatePathHint::DynamicMapChild);
                            }
                        }
                    }
                }
            }
        }
        // A join/loop temporary with more than one definition has no single
        // compile-time value. Keep every codegen and access-analysis fact map
        // fail-closed even if an earlier propagation pass encountered one arm.
        for key in &multiply_defined_dests {
            string_map.remove(key);
            dataref_kind_map.remove(key);
            state_path_hints.remove(key);
            int_const_map.remove(key);
            norito_literal_map.remove(key);
            instruction_literal_access_map.remove(key);
            string_literal_temps.remove(key);
            authority_account_temps.remove(key);
        }
        derive_state_access_hints(
            &ir_prog,
            &state_path_hints,
            &mut access_sets,
            &mut hint_diagnostics,
            &mut hint_skips,
        );
        for (func_idx, func) in ir_prog.functions.iter().enumerate() {
            for bb in &func.blocks {
                for instr in &bb.instrs {
                    if let ir::Instr::PointerFromString { kind, src, .. } = instr
                        && !string_map.contains_key(&(func_idx, *src))
                    {
                        let name = match kind {
                            ir::DataRefKind::Account => "account_id",
                            ir::DataRefKind::AssetDef => "asset_definition",
                            ir::DataRefKind::AssetId => "asset_id",
                            ir::DataRefKind::NftId => "nft_id",
                            ir::DataRefKind::Name => "name",
                            ir::DataRefKind::Json => "json",
                            ir::DataRefKind::Domain => "domain",
                            ir::DataRefKind::Blob => "blob",
                            ir::DataRefKind::NoritoBytes => "norito_bytes",
                            ir::DataRefKind::DataSpaceId => "dataspace_id",
                            ir::DataRefKind::AxtDescriptor => "axt_descriptor",
                            ir::DataRefKind::AxtAnchoredSpendV1 => "axt_anchored_spend_v1",
                            ir::DataRefKind::ProofBlob => "proof_blob",
                            ir::DataRefKind::SoracloudRequest => "soracloud_request",
                            ir::DataRefKind::SoracloudResponse => "soracloud_response",
                            ir::DataRefKind::Int => "int",
                            ir::DataRefKind::Decimal => "decimal",
                            ir::DataRefKind::Quantity => "quantity",
                        };
                        let msg =
                            format!("{name} expects a string literal; pass a literal or bytes");
                        return Err(i18n::translate(self.lang, Message::SemanticError(&msg)));
                    }
                }
            }
        }
        derive_isi_access_hints(
            &ir_prog,
            &string_map,
            &authority_account_temps,
            &dataref_kind_map,
            &instruction_literal_access_map,
            &mut access_sets,
            &mut hint_diagnostics,
            &mut hint_skips,
        );
        propagate_transitive_access_hints(&ir_prog, &mut access_sets, &mut hint_skips);
        let has_any_hints = access_sets
            .iter()
            .any(|set| !set.reads.is_empty() || !set.writes.is_empty());
        let include_hints = has_any_hints;
        let mut hint_reports = Vec::with_capacity(func_count);
        for skips in hint_skips.iter().take(func_count) {
            let skipped_reasons = skips.iter().cloned().collect::<Vec<_>>();
            hint_reports.push(HintReport {
                emitted: include_hints,
                complete: include_hints && skipped_reasons.is_empty(),
                skipped_reasons,
            });
        }
        // Data section builder and fixups.
        // Norito blobs for AccountId/AssetDefinitionId placed in data section
        let mut data_bytes: Vec<u8> = Vec::new();
        let mut data_offsets: HashMap<DataKey, u64> = HashMap::new();
        // Literal table fixups: each becomes one indexed pointer or scalar load.
        // Code-generation callbacks share this explicit compilation-local
        // recorder; there is no thread-local or process-global registry.
        let fixups = LiteralFixups::default();
        // Compile every function retained by whole-program reachability and stitch
        // them together. Track global code, per-function start offsets, and fixups
        // for inter-block control flow.
        // Raw execution never implies a source-level entrypoint. Offset zero is
        // deliberately non-dispatching; hosts must select a CNTR `entry_pc`.
        let mut code: Vec<u8> = Vec::new();
        push_word(&mut code, encoding::wide::encode_halt());
        let mut uses_zk_global = false;
        let mut uses_vector_global = false;
        let mut call_fixups: Vec<(usize, String, String)> = Vec::new();
        let mut deferred_transfers: Vec<DeferredTransfer> = Vec::new();
        // Each branch evaluates and stages its original descriptor/code first.
        // The terminal body belongs to the first emitting function's complete
        // byte range, and every other site reaches it with a normal relaxed jump.
        let share_nominal_abort = compact_emission::share_nominal_abort(&ir_prog);
        let mut nominal_abort_sites = Vec::new();
        let mut nominal_abort_tail = None;
        let mut func_start_offsets: HashMap<String, usize> = HashMap::new();
        let mut function_debug_seeds: Vec<FunctionDebugSeed> = Vec::new();
        let signatures = typed
            .items
            .iter()
            .map(|item| {
                let TypedItem::Function(function) = item;
                crate::call_abi::CallSignature::for_function(function)
                    .map(|signature| (function.name.clone(), signature))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;
        let mut callables = Vec::new();
        let mut function_sources = HashMap::new();
        for item in &typed.items {
            let TypedItem::Function(function) = item;
            function_sources.insert(function.name.clone(), function.source);
            function_sources.insert(entrypoint_ir_symbol_name(function), function.source);
        }
        struct JumpFixup {
            at: usize,
            target_label: usize,
        }
        enum BranchFixup {
            One {
                transfer_at: usize,
                target_label: usize,
            },
        }
        // Source declaration order must not select or privilege an entrypoint.
        let mut ordered_funcs: Vec<(usize, &ir::Function)> =
            ir_prog.functions.iter().enumerate().collect();
        ordered_funcs.sort_by(|(_, left), (_, right)| left.name.cmp(&right.name));
        for (func_idx, func) in ordered_funcs {
            // Record start offset for call patching
            func_start_offsets.insert(func.name.clone(), code.len());
            let func_base = *func_start_offsets.get(&func.name).unwrap();
            let initial_nominal_abort_sites = nominal_abort_sites.len();
            // Every retained function has one table ABI and an authenticated callable root.
            let is_entry = false;
            let saves_return_address = !is_entry && regalloc::has_internal_calls(func);
            let alloc = regalloc::allocate_with_splitting(func);
            let local_sources = local_emission::Plan::new(func, &alloc)?;
            let mut saved_regs: Vec<u8> = if is_entry {
                Vec::new()
            } else {
                alloc
                    .used_registers()
                    .into_iter()
                    .map(|register| register as u8)
                    .collect()
            };
            saved_regs.retain(|register| {
                !regalloc::CALLER_CLOBBERED_REGS.contains(&usize::from(*register))
            });
            saved_regs.sort_unstable();
            saved_regs.dedup();
            let state_value_table_words = func
                .blocks
                .iter()
                .flat_map(|block| block.instrs.iter())
                .filter_map(|instr| match instr {
                    Instr::StateValueEncode { words, .. } => Some(words.len()),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            let mut max_argument_words = 0;
            let mut max_result_words = 0;
            for instruction in func.blocks.iter().flat_map(|block| &block.instrs) {
                if let Instr::Call { callee, args, .. } | Instr::CallMulti { callee, args, .. } =
                    instruction
                {
                    let signature = signatures
                        .get(callee)
                        .ok_or_else(|| format!("missing call signature for `{callee}`"))?;
                    if args.len() != signature.argument_word_count() {
                        return Err(format!(
                            "call to `{callee}` has an inconsistent argument table"
                        ));
                    }
                    max_argument_words = max_argument_words.max(args.len());
                    max_result_words = max_result_words.max(signature.result_word_count());
                }
                match instruction {
                    Instr::InvokeEntrypointAs { .. } => max_result_words = max_result_words.max(1),
                    Instr::CallContract { dests, .. } => {
                        max_result_words = max_result_words.max(dests.len().max(1));
                    }
                    Instr::InvokeEntrypointAsMulti { dests, .. } => {
                        max_result_words = max_result_words.max(dests.len());
                    }
                    _ => {}
                }
            }
            let frame = crate::call_abi::CallFrameLayout::new(
                saves_return_address,
                alloc.frame_size,
                saved_regs.len(),
                state_value_table_words,
                max_argument_words,
                max_result_words,
            )?;
            let spill_base = frame.spill_base;
            let save_base = frame.save_base;
            let state_value_table_base = frame.state_table_base;
            let local_frame = frame.bytes;
            let signature = signatures
                .get(&func.name)
                .ok_or_else(|| format!("missing function signature for `{}`", func.name))?;
            callables.push(ivm_abi::call::EmbeddedCallableV1 {
                entry_pc: func_base as u64,
                frame_bytes: local_frame as u32,
                arguments: signature.arguments.clone(),
                results: signature.results.clone(),
            });
            let debug_seed_index = function_debug_seeds.len();
            function_debug_seeds.push(FunctionDebugSeed {
                name: func.name.clone(),
                location: func.location,
                source: function_sources.get(&func.name).copied().flatten(),
                pc_start: func_base as u64,
                pc_end: 0,
                frame_bytes: u32::try_from(local_frame).unwrap_or(u32::MAX),
            });
            let mut uses_zk = false;
            // Scratch registers for spill shuttling and SP alias
            let scratch1: u8 = 27;
            let scratch2: u8 = 28;
            let scratchd: u8 = 29;
            let sp = regalloc::SP_REG as u8;
            let allocation_position = std::cell::Cell::new(0usize);
            let retained_result = std::cell::Cell::new(None::<local_emission::RetainedResult>);
            let retained_register = |value: ir::Temp| {
                retained_result
                    .get()
                    .and_then(|result| result.register(value, allocation_position.get()))
            };
            let publish_tlv_word = encoding::wide::encode_sys(
                instruction::wide::system::SCALL,
                syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
            );
            let publish_tlv = publish_tlv_word.to_le_bytes();
            let push_syscall_imm8 = |code: &mut Vec<u8>, number: u32| {
                push_word(
                    code,
                    encoding::wide::encode_sys(instruction::wide::system::SCALL, number as u8),
                );
            };
            let pointer_to_word = encoding::wide::encode_sys(
                instruction::wide::system::SCALL,
                syscalls::SYSCALL_POINTER_TO_NORITO as u8,
            );
            let pointer_to_bytes = pointer_to_word.to_le_bytes();
            let pointer_from_word = encoding::wide::encode_sys(
                instruction::wide::system::SCALL,
                syscalls::SYSCALL_POINTER_FROM_NORITO as u8,
            );
            let pointer_from_bytes = pointer_from_word.to_le_bytes();
            let emit_split_reloads = |position: usize,
                                      tuples: &HashMap<ir::Temp, Vec<ir::Temp>>,
                                      code: &mut Vec<u8>|
             -> Result<(), String> {
                for reload in alloc.reloads_at(position) {
                    if tuples.contains_key(&reload.temp) {
                        // Product temporaries are compiler views over leaf words, not runtime
                        // words. Their unused spill homes have never been initialized.
                        continue;
                    }
                    let offset = alloc.stack.get(&reload.temp).ok_or_else(|| {
                        format!(
                            "split temporary {:?} has no canonical spill slot",
                            reload.temp
                        )
                    })?;
                    emit_load64(
                        code,
                        &fixups,
                        reload.register as u8,
                        sp,
                        stack_slot_offset_bytes(spill_base, *offset),
                        Some(scratch1),
                    )?;
                }
                Ok(())
            };
            // Helpers to handle spilled temporaries at use/def sites
            let src_reg = |t: &ir::Temp, scratch: u8, code: &mut Vec<u8>| -> Result<u8, String> {
                if let Some(register) = retained_register(*t) {
                    Ok(register)
                } else if let Some(register) = alloc.register_for_use(*t, allocation_position.get())
                {
                    Ok(register as u8)
                } else if let Some(off) = alloc.stack.get(t) {
                    let total = stack_slot_offset_bytes(spill_base, *off);
                    emit_load64(code, &fixups, scratch, sp, total, Some(scratch))?;
                    Ok(scratch)
                } else {
                    Ok(0)
                }
            };
            let literal_data_key = |temp: &ir::Temp, kind: ir::DataRefKind, value: &str| {
                // Strings and byte literals share the runtime Blob pointer ABI,
                // but only byte literals use the compiler's hex carrier spelling.
                // Keep source UTF-8 distinct at every rematerialization site.
                if kind == ir::DataRefKind::Blob
                    && string_literal_temps.contains(&(func_idx, *temp))
                {
                    DataKey(DataKind::String, value.to_owned())
                } else {
                    data_key_for_pointer(kind, value)
                }
            };
            let emit_syscall_values_with_kinds = |values: &[ir::Temp],
                                                  pointer_kinds: Option<&[DataKind]>,
                                                  code: &mut Vec<u8>|
             -> Result<(), String> {
                let mut register_moves = Vec::new();
                let mut literal_loads = Vec::new();
                let mut stack_loads = Vec::new();
                let mut zero_loads = Vec::new();
                for (index, temp) in values.iter().enumerate() {
                    let target = regalloc::CALLER_CLOBBERED_REGS
                        .get(index)
                        .copied()
                        .ok_or_else(|| "syscall argument register window is exhausted".to_owned())?
                        as u8;
                    if let Some(kinds) = pointer_kinds
                        && let Some(value) = string_map.get(&(func_idx, *temp)).cloned()
                    {
                        // Preserve each pointer emitter's exact literal kind, including
                        // StatePath/NoritoBytes and Name map bases. Dynamic sources still
                        // use the same parallel register/spill custody below.
                        literal_loads.push((
                            target,
                            DataKey(
                                *kinds.get(index).ok_or_else(|| {
                                    "syscall pointer argument kind is missing".to_owned()
                                })?,
                                value,
                            ),
                        ));
                    } else if let Some(kind) = dataref_kind_map.get(&(func_idx, *temp)).copied()
                        && let Some(value) = string_map.get(&(func_idx, *temp)).cloned()
                    {
                        literal_loads.push((target, literal_data_key(temp, kind, &value)));
                    } else if let Some(source) = retained_register(*temp) {
                        register_moves.push((target, source));
                    } else if let Some(source) =
                        alloc.register_for_use(*temp, allocation_position.get())
                    {
                        register_moves.push((target, source as u8));
                    } else if let Some(offset) = alloc.stack.get(temp) {
                        stack_loads.push((target, stack_slot_offset_bytes(spill_base, *offset)));
                    } else {
                        zero_loads.push(target);
                    }
                }
                // Consume every register source before a literal or stack
                // materialization overwrites an ABI destination. Cycles
                // use the dedicated non-allocatable scratch register.
                emit_parallel_register_moves(code, register_moves, scratch1)?;
                for (target, key) in literal_loads {
                    emit_literal_load(code, &fixups, target, key);
                }
                for (target, offset) in stack_loads {
                    emit_load64(code, &fixups, target, sp, offset, Some(scratch1))?;
                }
                for target in zero_loads {
                    push_word(code, encode_addi(target, 0, 0)?);
                }
                Ok(())
            };
            let emit_values_to_syscall_registers = |values: &[ir::Temp], code: &mut Vec<u8>| {
                emit_syscall_values_with_kinds(values, None, code)
            };
            let emit_numeric_operands =
                |left: &ir::Temp, right: &ir::Temp, code: &mut Vec<u8>| -> Result<(), String> {
                    // Preserve the original codegen rejection before loading either
                    // operand. This does not replace canonical literal validation.
                    for temp in [left, right] {
                        if string_map.contains_key(&(func_idx, *temp))
                            && !dataref_kind_map.contains_key(&(func_idx, *temp))
                        {
                            return Err(i18n::translate(
                                self.lang,
                                Message::SemanticError(
                                    "numeric literal missing ABI metadata during numeric lowering",
                                ),
                            ));
                        }
                    }
                    // Only the test binary retains the former publication sequence,
                    // to measure the same compiler before/after this lowering change.
                    #[cfg(test)]
                    if numeric_operands::retain_publication() {
                        for (index, temp) in [left, right].into_iter().enumerate() {
                            if let Some(kind) = dataref_kind_map.get(&(func_idx, *temp)).copied()
                                && let Some(value) = string_map.get(&(func_idx, *temp))
                            {
                                emit_literal_load(
                                    code,
                                    &fixups,
                                    10,
                                    literal_data_key(temp, kind, value),
                                );
                            } else {
                                let source = src_reg(temp, scratch1, code)?;
                                push_word(code, encode_addi(10, source, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            if index == 0 {
                                push_word(code, encode_addi(scratch2, 10, 0)?);
                            } else {
                                push_word(code, encode_addi(11, 10, 0)?);
                                push_word(code, encode_addi(10, scratch2, 0)?);
                            }
                        }
                        return Ok(());
                    }
                    // The canonical numeric syscall snapshots both public operands
                    // through numeric_tlv::snapshot_metered. It admits loader-validated
                    // immutable literals, INPUT and owned HEAP; checks pointer type,
                    // complete envelope/hash/frame, and charges its original work.
                    // It retains no pointer after the synchronous operation. Passing
                    // these pointers directly removes only the preceding redundant
                    // INPUT_PUBLISH and its shuffles, not the typed numeric boundary.
                    // Existing parallel staging consumes all register sources before
                    // materializing literals/spills, including swapped/aliased inputs.
                    emit_values_to_syscall_registers(&[*left, *right], code)
                };
            let dst_reg = |t: &ir::Temp| -> (u8, bool, i64) {
                if let Some(r) = alloc.regs.get(t) {
                    (*r as u8, false, 0)
                } else if let Some(off) = alloc.stack.get(t) {
                    (scratchd, true, stack_slot_offset_bytes(spill_base, *off))
                } else {
                    (scratchd, false, 0)
                }
            };
            let spill_back = |_: &ir::Temp,
                              from: u8,
                              spilled: bool,
                              offset: i64,
                              code: &mut Vec<u8>|
             -> Result<(), String> {
                if spilled {
                    emit_store64(code, &fixups, sp, from, offset, scratch2)?;
                }
                Ok(())
            };
            let load_pointer = |temp: &ir::Temp,
                                target: u8,
                                scratch: u8,
                                kind: DataKind,
                                code: &mut Vec<u8>|
             -> Result<(), String> {
                if let Some(value) = string_map.get(&(func_idx, *temp)) {
                    let kind = if kind == DataKind::Blob
                        && string_literal_temps.contains(&(func_idx, *temp))
                    {
                        DataKind::String
                    } else {
                        kind
                    };
                    emit_literal_load(code, &fixups, target, DataKey(kind, value.clone()));
                } else {
                    let source = src_reg(temp, scratch, code)?;
                    push_word(code, encode_addi(target, source, 0)?);
                }
                Ok(())
            };
            let spill_syscall_result =
                |dest: &ir::Temp, code: &mut Vec<u8>| -> Result<(), String> {
                    if let Some(result) = local_sources.output(*dest, allocation_position.get()) {
                        retained_result.set(Some(result));
                        return Ok(());
                    }
                    let (rd, spilled, offset) = dst_reg(dest);
                    local_emission::emit_move(code, rd, 10)?;
                    spill_back(dest, rd, spilled, offset, code)
                };
            let shared_epilogue = frame_emission::shared_epilogue_label(func, saved_regs.len());
            let mut block_offsets: HashMap<usize, usize> = HashMap::new();
            let mut jump_fixups: Vec<JumpFixup> = Vec::new();
            let mut branch_fixups: Vec<BranchFixup> = Vec::new();
            // Tuple materialization map per function
            let mut tuple_map: std::collections::HashMap<ir::Temp, Vec<ir::Temp>> =
                Default::default();
            let mut next_allocation_position = 0usize;
            for (block_index, bb) in func.blocks.iter().enumerate() {
                // This block begins with no inherited physical-register facts.
                let mut numeric_zero = numeric_zero::Block::new(code.len());
                let next_label = func.blocks.get(block_index + 1).map(|next| next.label);
                block_offsets.insert(bb.label.0, code.len() - func_base);
                // Emit a frame only when spills, callee-saved registers, or a
                // nested-call return address actually require one.
                if bb.label == func.entry && local_frame > 0 {
                    let sp = regalloc::SP_REG as u8;
                    emit_bounded_add(
                        &mut code,
                        &fixups,
                        sp,
                        sp,
                        -(local_frame as i64),
                        LITERAL_SHIFT_REG,
                    )?;
                    let scratch_base = if sp != scratch1 { scratch1 } else { scratch2 };
                    if saves_return_address {
                        let ra = 1u8;
                        emit_store64(&mut code, &fixups, sp, ra, 0, scratch_base)?;
                    }
                    if local_sources.stores_argument_base {
                        emit_store64(
                            &mut code,
                            &fixups,
                            sp,
                            10,
                            frame.argument_base_slot as i64,
                            scratch_base,
                        )?;
                    }
                    emit_store64(
                        &mut code,
                        &fixups,
                        sp,
                        12,
                        frame.result_base_slot as i64,
                        scratch_base,
                    )?;
                    frame_emission::emit_saved_registers(
                        &mut code,
                        &fixups,
                        &saved_regs,
                        save_base,
                        false,
                    )?;
                }
                if bb.label == func.entry && local_sources.parameter_prefix_words > 0 {
                    // The incoming authenticated table is already captured by
                    // the original call kernel. Keep its exact base through the
                    // consecutive parameter reads; private frame geometry stays.
                    local_emission::emit_move(&mut code, scratch1, 10)?;
                }
                let fused_relational = match (&bb.terminator, bb.instrs.last()) {
                    (
                        Terminator::Branch { cond, .. },
                        Some(Instr::Binary {
                            dest,
                            op,
                            left,
                            right,
                        }),
                    ) if dest == cond
                        && matches!(
                            op,
                            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge
                        ) =>
                    {
                        Some((*op, *left, *right))
                    }
                    _ => None,
                };
                #[cfg(test)]
                let mut emission_observation = None;
                for (instruction_index, instr) in bb.instrs.iter().enumerate() {
                    let instruction_start = code.len();
                    #[cfg(test)]
                    emission_profile::advance(
                        &mut emission_observation,
                        &func.name,
                        instr,
                        code.len(),
                    );
                    allocation_position.set(next_allocation_position);
                    emit_split_reloads(next_allocation_position, &tuple_map, &mut code)?;
                    next_allocation_position = next_allocation_position.saturating_add(1);
                    if fused_relational.is_some() && instruction_index + 1 == bb.instrs.len() {
                        // The terminator emits the signed comparison directly as
                        // BLT/BGE. Materializing a separate boolean here would
                        // add dead work and defeat compare-branch fusion.
                        continue;
                    }
                    match instr {
                        Instr::Source(_) => {
                            unreachable!("source transport is removed before code generation")
                        }
                        Instr::StringConst { dest, value } => {
                            // Materialize string literals as Blob pointers via the literal table.
                            let (rd, spilled, imm) = dst_reg(dest);
                            let key = DataKey(DataKind::String, value.clone());
                            emit_literal_load(&mut code, &fixups, rd, key);
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Const { dest, value } => {
                            let (rd, spilled, imm) = dst_reg(dest);
                            let imm_val = *value;
                            if ((WIDE_IMM_MIN as i64)..=(WIDE_IMM_MAX as i64)).contains(&imm_val) {
                                emit_addi(&mut code, rd, 0, imm_val);
                            } else {
                                emit_i64_literal_load(&mut code, &fixups, rd, imm_val);
                            }
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::TuplePack { dest, items } => {
                            tuple_map.insert(*dest, items.clone());
                            // no code
                        }
                        Instr::TupleGet { dest, tuple, index } => {
                            // rd = item(index)
                            let (rd, spilled, imm) = dst_reg(dest);
                            let tuple_items = tuple_map.get(tuple).cloned();
                            if let Some(items) = tuple_items {
                                if let Some(src_t) = items.get(*index) {
                                    if let Some(child_items) = tuple_map.get(src_t).cloned() {
                                        // Selecting a nested product only selects its leaf view;
                                        // no aggregate register or stack slot exists to copy.
                                        tuple_map.insert(*dest, child_items);
                                        continue;
                                    }
                                    if let (Some(kind), Some(literal)) = (
                                        dataref_kind_map.get(&(func_idx, *src_t)).copied(),
                                        string_map.get(&(func_idx, *src_t)).cloned(),
                                    ) {
                                        let key = literal_data_key(src_t, kind, &literal);
                                        emit_literal_load(&mut code, &fixups, rd, key);
                                    } else {
                                        let rs = src_reg(src_t, scratch1, &mut code)?;
                                        emit_addi(&mut code, rd, rs, 0);
                                    }
                                    tuple_map.remove(dest);
                                } else {
                                    // Out of bounds: move zero
                                    emit_addi(&mut code, rd, 0, 0);
                                    tuple_map.remove(dest);
                                }
                            } else {
                                // Unknown tuple: move zero
                                emit_addi(&mut code, rd, 0, 0);
                                tuple_map.remove(dest);
                            }
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Binary {
                            dest,
                            op,
                            left,
                            right,
                        } => {
                            if *op == BinaryOp::Add {
                                let left_zero =
                                    int_const_map.get(&(func_idx, *left)) == Some(&0i64);
                                let right_zero =
                                    int_const_map.get(&(func_idx, *right)) == Some(&0i64);
                                if let Some(kind) =
                                    dataref_kind_map.get(&(func_idx, *left)).copied()
                                    && let Some(lit) = string_map.get(&(func_idx, *left)).cloned()
                                    && right_zero
                                {
                                    let (rd, spilled, imm) = dst_reg(dest);
                                    let key = literal_data_key(left, kind, &lit);
                                    emit_literal_load(&mut code, &fixups, rd, key);
                                    spill_back(dest, rd, spilled, imm, &mut code)?;
                                    continue;
                                } else if let Some(kind) =
                                    dataref_kind_map.get(&(func_idx, *right)).copied()
                                    && let Some(lit) = string_map.get(&(func_idx, *right)).cloned()
                                    && left_zero
                                {
                                    let (rd, spilled, imm) = dst_reg(dest);
                                    let key = literal_data_key(right, kind, &lit);
                                    emit_literal_load(&mut code, &fixups, rd, key);
                                    spill_back(dest, rd, spilled, imm, &mut code)?;
                                    continue;
                                } else if left_zero || right_zero {
                                    let (rd, spilled, imm) = dst_reg(dest);
                                    let src = if left_zero { right } else { left };
                                    let rs = src_reg(src, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(rd, rs, 0)?);
                                    spill_back(dest, rd, spilled, imm, &mut code)?;
                                    continue;
                                }
                            }
                            let (rd, spilled, imm) = dst_reg(dest);
                            let rs1 = src_reg(left, scratch1, &mut code)?;
                            let rs2 = src_reg(right, scratch2, &mut code)?;
                            match op {
                                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => {
                                    // Source numeric arithmetic never reaches scalar IR: it uses
                                    // the Int/Decimal/Quantity syscalls. Scalar arithmetic here is
                                    // compiler-owned bounded control-flow and layout bookkeeping.
                                    let opcode = match op {
                                        BinaryOp::Add => instruction::wide::arithmetic::ADD,
                                        BinaryOp::Sub => instruction::wide::arithmetic::SUB,
                                        BinaryOp::Mul => instruction::wide::arithmetic::MUL,
                                        _ => unreachable!(),
                                    };
                                    push_word(
                                        &mut code,
                                        encoding::wide::encode_rr(opcode, rd, rs1, rs2),
                                    );
                                }
                                BinaryOp::And => {
                                    let word = encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::AND,
                                        rd,
                                        rs1,
                                        rs2,
                                    );
                                    push_word(&mut code, word);
                                }
                                BinaryOp::Or => {
                                    let word = encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::OR,
                                        rd,
                                        rs1,
                                        rs2,
                                    );
                                    push_word(&mut code, word);
                                }
                                BinaryOp::Eq => {
                                    let word = encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::SEQ,
                                        rd,
                                        rs1,
                                        rs2,
                                    );
                                    push_word(&mut code, word);
                                }
                                BinaryOp::Ne => {
                                    let word = encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::SNE,
                                        rd,
                                        rs1,
                                        rs2,
                                    );
                                    push_word(&mut code, word);
                                }
                                BinaryOp::Lt | BinaryOp::Gt | BinaryOp::Le | BinaryOp::Ge => {
                                    let (a, b, invert) = signed_compare_plan(*op, rs1, rs2)
                                        .expect("relational operator has a signed comparison plan");
                                    push_word(
                                        &mut code,
                                        encoding::wide::encode_rr(
                                            instruction::wide::arithmetic::SLT,
                                            rd,
                                            a,
                                            b,
                                        ),
                                    );
                                    if invert {
                                        push_word(
                                            &mut code,
                                            encoding::wide::encode_ri(
                                                instruction::wide::arithmetic::XORI,
                                                rd,
                                                rd,
                                                1,
                                            ),
                                        );
                                    }
                                }
                                BinaryOp::Div => push_word(
                                    &mut code,
                                    encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::DIV,
                                        rd,
                                        rs1,
                                        rs2,
                                    ),
                                ),
                                BinaryOp::Mod => push_word(
                                    &mut code,
                                    encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::REM,
                                        rd,
                                        rs1,
                                        rs2,
                                    ),
                                ),
                            }
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::WrappingBinary {
                            dest,
                            op,
                            left,
                            right,
                        } => {
                            let load_int = |temp: &ir::Temp,
                                            target: u8,
                                            scratch: u8,
                                            code: &mut Vec<u8>|
                             -> Result<(), String> {
                                if let Some(literal) = string_map.get(&(func_idx, *temp)).cloned() {
                                    emit_literal_load(
                                        code,
                                        &fixups,
                                        target,
                                        DataKey(DataKind::Int, literal),
                                    );
                                } else {
                                    let source = src_reg(temp, scratch, code)?;
                                    push_word(code, encode_addi(target, source, 0)?);
                                }
                                Ok(())
                            };
                            load_int(left, 10, scratch1, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                            load_int(right, 10, scratch1, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch2, 0)?);
                            let syscall = match op {
                                BinaryOp::Add => syscalls::SYSCALL_INT_WRAP_ADD,
                                BinaryOp::Sub => syscalls::SYSCALL_INT_WRAP_SUB,
                                BinaryOp::Mul => syscalls::SYSCALL_INT_WRAP_MUL,
                                _ => unreachable!("wrapping binary IR accepts only +, -, and *"),
                            };
                            push_syscall(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Unary { dest, op, operand } => {
                            let (rd, spilled, imm) = dst_reg(dest);
                            let rs = src_reg(operand, scratch1, &mut code)?;
                            match op {
                                UnaryOp::Neg => {
                                    push_word(
                                        &mut code,
                                        encoding::wide::encode_rr(
                                            instruction::wide::arithmetic::NEG,
                                            rd,
                                            rs,
                                            0,
                                        ),
                                    );
                                }
                                UnaryOp::Not => {
                                    // boolean not (0/1) via XORI with 1
                                    push_word(
                                        &mut code,
                                        encoding::wide::encode_ri(
                                            instruction::wide::arithmetic::XORI,
                                            rd,
                                            rs,
                                            1,
                                        ),
                                    );
                                }
                            }
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::WrappingNeg { dest, operand } => {
                            if let Some(literal) = string_map.get(&(func_idx, *operand)).cloned() {
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    10,
                                    DataKey(DataKind::Int, literal),
                                );
                            } else {
                                let source = src_reg(operand, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, source, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_INT_WRAP_NEG);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Abs { dest, src } | Instr::Isqrt { dest, src } => {
                            let (rd, spilled, imm) = dst_reg(dest);
                            let rs = src_reg(src, scratch1, &mut code)?;
                            let opcode = match instr {
                                Instr::Abs { .. } => instruction::wide::arithmetic::ABS,
                                Instr::Isqrt { .. } => instruction::wide::arithmetic::ISQRT,
                                _ => unreachable!(),
                            };
                            let word = encoding::wide::encode_rr(opcode, rd, rs, 0);
                            push_word(&mut code, word);
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Min { dest, a, b }
                        | Instr::Max { dest, a, b }
                        | Instr::DivCeil {
                            dest,
                            num: a,
                            denom: b,
                        }
                        | Instr::Gcd { dest, a, b }
                        | Instr::Mean { dest, a, b } => {
                            let (rd, spilled, imm) = dst_reg(dest);
                            let rs1 = src_reg(a, scratch1, &mut code)?;
                            let rs2 = src_reg(b, scratch2, &mut code)?;
                            let opcode = match instr {
                                Instr::Min { .. } => instruction::wide::arithmetic::MIN,
                                Instr::Max { .. } => instruction::wide::arithmetic::MAX,
                                Instr::DivCeil { .. } => instruction::wide::arithmetic::DIV_CEIL,
                                Instr::Gcd { .. } => instruction::wide::arithmetic::GCD,
                                Instr::Mean { .. } => instruction::wide::arithmetic::MEAN,
                                _ => unreachable!(),
                            };
                            push_word(&mut code, encoding::wide::encode_rr(opcode, rd, rs1, rs2));
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Copy { dest, src } => {
                            if let Some(items) = tuple_map.get(src).cloned() {
                                tuple_map.insert(*dest, items);
                                continue;
                            }
                            tuple_map.remove(dest);
                            let (rd, spilled, imm) = dst_reg(dest);
                            if let Some(kind) = dataref_kind_map.get(&(func_idx, *src)).copied()
                                && let Some(lit) = string_map.get(&(func_idx, *src)).cloned()
                            {
                                let key = literal_data_key(src, kind, &lit);
                                emit_literal_load(&mut code, &fixups, rd, key);
                            } else {
                                let rs = src_reg(src, scratch1, &mut code)?;
                                if rd != rs {
                                    push_word(&mut code, encode_addi(rd, rs, 0)?);
                                }
                            }
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::LoadVar { dest, name } => {
                            let (rd, spilled, imm) = dst_reg(dest);
                            let idx =
                                func.params.iter().position(|p| p == name).ok_or_else(|| {
                                    i18n::translate(self.lang, Message::UnknownParam(name))
                                })?;
                            if bb.label != func.entry
                                || instruction_index >= local_sources.parameter_prefix_words
                            {
                                emit_load64(
                                    &mut code,
                                    &fixups,
                                    scratch1,
                                    sp,
                                    frame.argument_base_slot as i64,
                                    Some(scratch2),
                                )?;
                            }
                            emit_load64(
                                &mut code,
                                &fixups,
                                rd,
                                scratch1,
                                (idx * 8) as i64,
                                Some(scratch2),
                            )?;
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Poseidon2 { dest, a, b } => {
                            uses_zk = true;
                            let (rd, spilled, imm) = dst_reg(dest);
                            let rs1 = src_reg(a, scratch1, &mut code)?;
                            let rs2 = src_reg(b, scratch2, &mut code)?;
                            let word = encoding::wide::encode_poseidon2(rd, rs1, rs2);
                            push_word(&mut code, word);
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Pubkgen { .. } | Instr::Valcom { .. } => {
                            return Err(
                                "retired scalar cryptography reached bytecode emission".to_owned()
                            );
                        }
                        Instr::PrivateNumericValcom { dest, value, blind } => {
                            uses_zk = true;
                            let value_register = src_reg(value, scratch1, &mut code)?;
                            let blind_register = src_reg(blind, scratch2, &mut code)?;
                            emit_private_numeric_valcom_arguments(
                                &mut code,
                                value_register,
                                blind_register,
                                scratchd,
                            )?;
                            push_syscall(&mut code, syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::MintAsset {
                            account,
                            asset,
                            amount,
                        } => {
                            // Pointer-ABI: accept literal pointers (from string_map) or runtime pointers.
                            if int_const_map.contains_key(&(func_idx, *account))
                                || int_const_map.contains_key(&(func_idx, *asset))
                            {
                                return Err(i18n::translate(
                                    self.lang,
                                    Message::UnsupportedBinaryOp(
                                        "mint_asset expects (account, asset) pointers",
                                    ),
                                ));
                            }
                            // r10 = &AccountId
                            load_pointer(account, 10, scratch1, DataKind::Account, &mut code)?;
                            // r11 = &AssetDefinitionId
                            load_pointer(asset, 11, scratch2, DataKind::AssetDef, &mut code)?;
                            // r12 = canonical &Quantity
                            if let Some(key) = quantity_literal_data_key(
                                func_idx,
                                *amount,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 12, key);
                            } else {
                                let r_amt = src_reg(amount, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(12, r_amt, 0)?);
                            }
                            // Mirror TLVs for r10 and r11 into INPUT to satisfy pointer-ABI validation.
                            // Publish r10 and preserve it in x13.
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(13, 10, 0)?);
                            // Publish r11: x10 <- x11; publish; x11 <- x10.
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            // Publish r12 (amount): x10 <- x12; publish; x12 <- x10.
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            // Restore account pointer: x10 <- x13.
                            push_word(&mut code, encode_addi(10, 13, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_MINT_ASSET);
                        }
                        Instr::BurnAsset {
                            account,
                            asset,
                            amount,
                        } => {
                            // r10 = &AccountId
                            load_pointer(account, 10, scratch2, DataKind::Account, &mut code)?;
                            // r11 = &AssetDefinitionId
                            load_pointer(asset, 11, scratch2, DataKind::AssetDef, &mut code)?;
                            if let Some(key) = quantity_literal_data_key(
                                func_idx,
                                *amount,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 12, key);
                            } else {
                                let r_amt = src_reg(amount, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(12, r_amt, 0)?);
                            }
                            // Mirror TLVs for r10 and r11 into INPUT to satisfy pointer‑ABI validation.
                            // Publish r10 and preserve it in x13.
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(13, 10, 0)?);
                            // Publish r11: x10 <- x11; publish; x11 <- x10.
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            // Publish r12 (amount): x10 <- x12; publish; x12 <- x10.
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            // Restore account pointer: x10 <- x13.
                            push_word(&mut code, encode_addi(10, 13, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_BURN_ASSET);
                        }
                        Instr::RegisterDomain { domain } => {
                            // Pointer-ABI: load DomainId TLV pointer into x10; or move from runtime pointer.
                            if let Some(dom_str) = string_map.get(&(func_idx, *domain)) {
                                let key_dom = DataKey(DataKind::Domain, dom_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_dom);
                            } else {
                                let r_dom = src_reg(domain, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_dom, 0)?);
                            }
                            // Mirror TLV into INPUT to satisfy pointer‑ABI validation in hosts.
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_REGISTER_DOMAIN);
                        }
                        Instr::UnregisterDomain { domain } => {
                            if let Some(dom_str) = string_map.get(&(func_idx, *domain)) {
                                let key_dom = DataKey(DataKind::Domain, dom_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_dom);
                            } else {
                                let r_dom = src_reg(domain, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_dom, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_UNREGISTER_DOMAIN);
                        }
                        Instr::UnregisterAccount { account } => {
                            if let Some(acc_str) = string_map.get(&(func_idx, *account)) {
                                let key_acc = DataKey(DataKind::Account, acc_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_acc);
                            } else {
                                let r = src_reg(account, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_UNREGISTER_ACCOUNT);
                        }
                        Instr::RegisterAccount { account } => {
                            if let Some(acc_str) = string_map.get(&(func_idx, *account)) {
                                let key_acc = DataKey(DataKind::Account, acc_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_acc);
                            } else {
                                let r = src_reg(account, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_REGISTER_ACCOUNT);
                        }
                        Instr::AddSignatory { account, signatory }
                        | Instr::RemoveSignatory { account, signatory } => {
                            if let Some(acc_str) = string_map.get(&(func_idx, *account)) {
                                let key_acc = DataKey(DataKind::Account, acc_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_acc);
                            } else {
                                let r = src_reg(account, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            if let Some(json) = string_map.get(&(func_idx, *signatory)) {
                                let key_json = DataKey(DataKind::Json, json.clone());
                                emit_literal_load(&mut code, &fixups, 11, key_json);
                            } else {
                                let r = src_reg(signatory, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(11, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            let syscall = match instr {
                                Instr::AddSignatory { .. } => syscalls::SYSCALL_ADD_SIGNATORY,
                                _ => syscalls::SYSCALL_REMOVE_SIGNATORY,
                            };
                            push_syscall(&mut code, syscall);
                        }
                        Instr::SetAccountQuorum { account, quorum } => {
                            if let Some(acc_str) = string_map.get(&(func_idx, *account)) {
                                let key_acc = DataKey(DataKind::Account, acc_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_acc);
                            } else {
                                let r = src_reg(account, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            let r_quorum = src_reg(quorum, scratch2, &mut code)?;
                            push_word(&mut code, encode_addi(11, r_quorum, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_SET_ACCOUNT_QUORUM);
                        }
                        Instr::UnregisterAsset { asset } => {
                            load_pointer(asset, 10, scratch1, DataKind::AssetDef, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_UNREGISTER_ASSET);
                        }
                        Instr::TransferDomain { domain, to } => {
                            // Load domain into x10 and publish; keep a copy in x12
                            if let Some(dom_str) = string_map.get(&(func_idx, *domain)) {
                                let key_dom = DataKey(DataKind::Domain, dom_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_dom);
                            } else {
                                let r_dom = src_reg(domain, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_dom, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?); // x12 = x10
                            // Load 'to' AccountId into x11
                            if let Some(to_str) = string_map.get(&(func_idx, *to)) {
                                let key_to = DataKey(DataKind::Account, to_str.clone());
                                emit_literal_load(&mut code, &fixups, 11, key_to);
                            } else {
                                let r_to = src_reg(to, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(11, r_to, 0)?);
                            }
                            // Publish 'to' TLV: x10 <- x11; publish; x11 <- x10
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            // Restore domain pointer: x10 <- x12
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            // SCALL transfer
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_TRANSFER_DOMAIN);
                        }
                        Instr::RegisterPeer { json } => {
                            // r10 = &Json
                            load_pointer(json, 10, scratch1, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_REGISTER_PEER);
                        }
                        Instr::UnregisterPeer { json } => {
                            load_pointer(json, 10, scratch1, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_UNREGISTER_PEER);
                        }
                        Instr::CreateTrigger { json } => {
                            load_pointer(json, 10, scratch1, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_CREATE_TRIGGER);
                        }
                        Instr::RemoveTrigger { name } => {
                            load_pointer(name, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_REMOVE_TRIGGER);
                        }
                        Instr::SetTriggerEnabled { name, enabled } => {
                            load_pointer(name, 10, scratch1, DataKind::Name, &mut code)?;
                            // enabled value to r11
                            let r_en = src_reg(enabled, scratch2, &mut code)?;
                            push_word(&mut code, encode_addi(11, r_en, 0)?);
                            // Mirror name TLV
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_SET_TRIGGER_ENABLED);
                        }
                        Instr::CreateRole { name, json } => {
                            // r10 = &Name, r11 = &Json
                            load_pointer(name, 10, scratch1, DataKind::Name, &mut code)?;
                            load_pointer(json, 11, scratch2, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv); // r10
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_CREATE_ROLE);
                        }
                        Instr::DeleteRole { name } => {
                            load_pointer(name, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_DELETE_ROLE);
                        }
                        Instr::GrantRole { account, name }
                        | Instr::RevokeRole { account, name } => {
                            // r10=&AccountId, r11=&Name
                            load_pointer(account, 10, scratch1, DataKind::Account, &mut code)?;
                            load_pointer(name, 11, scratch2, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv); // r10
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            let num = match instr {
                                Instr::GrantRole { .. } => syscalls::SYSCALL_GRANT_ROLE,
                                _ => syscalls::SYSCALL_REVOKE_ROLE,
                            };
                            push_syscall_imm8(&mut code, num);
                        }
                        Instr::GrantPermission { account, token }
                        | Instr::RevokePermission { account, token } => {
                            // r10 = &AccountId; r11 = &Name or &Json
                            load_pointer(account, 10, scratch1, DataKind::Account, &mut code)?;
                            // token pointer
                            if let Some(nm) = string_map.get(&(func_idx, *token)) {
                                // Assume Name unless starts with '{' then Json
                                let dk = if nm.starts_with("{") {
                                    DataKey(DataKind::Json, nm.clone())
                                } else {
                                    DataKey(DataKind::Name, nm.clone())
                                };
                                emit_literal_load(&mut code, &fixups, 11, dk);
                            } else {
                                let r = src_reg(token, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(11, r, 0)?);
                            }
                            // Mirror both
                            code.extend_from_slice(&publish_tlv); // r10
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            let num = match instr {
                                Instr::GrantPermission { .. } => syscalls::SYSCALL_GRANT_PERMISSION,
                                _ => syscalls::SYSCALL_REVOKE_PERMISSION,
                            };
                            push_syscall_imm8(&mut code, num);
                        }
                        Instr::GrantContractPermission {
                            account,
                            permission,
                        }
                        | Instr::RevokeContractPermission {
                            account,
                            permission,
                        } => {
                            // r10 = &AccountId; r11 = &Name containing the declared permission name.
                            load_pointer(account, 10, scratch1, DataKind::Account, &mut code)?;
                            load_pointer(permission, 11, scratch2, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            let number = match instr {
                                Instr::GrantContractPermission { .. } => {
                                    syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION
                                }
                                _ => syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION,
                            };
                            push_syscall_imm8(&mut code, number);
                        }
                        Instr::ZkVerify { number, payload } => {
                            // Load/move payload pointer into x10
                            load_pointer(payload, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            // Mirror into INPUT to satisfy pointer‑ABI validation
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, *number);
                            uses_zk = true;
                        }
                        Instr::ExecutionSummary { dest } => {
                            push_syscall(&mut code, syscalls::SYSCALL_EXECUTION_SUMMARY);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Alloc { dest, bytes } => {
                            let r = src_reg(bytes, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, r, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_ALLOC);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::GrowHeap { dest, bytes } => {
                            let r = src_reg(bytes, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, r, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_GROW_HEAP);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::GetMerklePath {
                            dest,
                            address,
                            output,
                            root_output,
                        } => {
                            let address_reg = src_reg(address, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, address_reg, 0)?);
                            let output_reg = src_reg(output, scratch2, &mut code)?;
                            push_word(&mut code, encode_addi(11, output_reg, 0)?);
                            if let Some(root_output) = root_output {
                                let root_reg = src_reg(root_output, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(12, root_reg, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(12, 0, 0)?);
                            }
                            push_syscall(&mut code, syscalls::SYSCALL_GET_MERKLE_PATH);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::GetMerkleCompact {
                            dest,
                            address,
                            output,
                            max_depth,
                            root_output,
                        } => {
                            let address_reg = src_reg(address, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, address_reg, 0)?);
                            let output_reg = src_reg(output, scratch2, &mut code)?;
                            push_word(&mut code, encode_addi(11, output_reg, 0)?);
                            if let Some(max_depth) = max_depth {
                                let depth_reg = src_reg(max_depth, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(12, depth_reg, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(12, 0, 0)?);
                            }
                            if let Some(root_output) = root_output {
                                let root_reg = src_reg(root_output, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(13, root_reg, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(13, 0, 0)?);
                            }
                            push_syscall(&mut code, syscalls::SYSCALL_GET_MERKLE_COMPACT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::GetRegisterMerkleCompact {
                            dest,
                            register_index,
                            output,
                            max_depth,
                            root_output,
                        } => {
                            let index_reg = src_reg(register_index, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, index_reg, 0)?);
                            let output_reg = src_reg(output, scratch2, &mut code)?;
                            push_word(&mut code, encode_addi(11, output_reg, 0)?);
                            if let Some(max_depth) = max_depth {
                                let depth_reg = src_reg(max_depth, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(12, depth_reg, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(12, 0, 0)?);
                            }
                            if let Some(root_output) = root_output {
                                let root_reg = src_reg(root_output, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(13, root_reg, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(13, 0, 0)?);
                            }
                            push_syscall(&mut code, syscalls::SYSCALL_GET_REGISTER_MERKLE_COMPACT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::VerifyProof { dest, payload } => {
                            load_pointer(payload, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_VERIFY_PROOF);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::VendorExecuteInstruction { payload, kind } => {
                            load_pointer(payload, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            // Mirror into INPUT to satisfy pointer‑ABI validation
                            code.extend_from_slice(&publish_tlv);
                            let operation_tag = match kind {
                                ir::VendorInstructionKind::SubmitBallot => {
                                    syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT
                                }
                            };
                            push_word(
                                &mut code,
                                encode_addi(
                                    11,
                                    0,
                                    i16::try_from(operation_tag)
                                        .expect("instruction operation tag fits i16"),
                                )?,
                            );
                            push_syscall_imm8(
                                &mut code,
                                syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
                            );
                        }
                        Instr::VendorExecuteQuery { dest, payload } => {
                            load_pointer(payload, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            // Mirror into INPUT to satisfy pointer‑ABI validation
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(
                                &mut code,
                                syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY,
                            );
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::QueryExecuteNorito { dest, payload } => {
                            load_pointer(payload, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_QUERY_EXECUTE_NORITO);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::QueryGet { dest, key, syscall } => {
                            let r = src_reg(key, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, r, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, *syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::CoreQueryGet { dest, key, entity } => {
                            let rkey = src_reg(key, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, rkey, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            emit_addi(&mut code, 10, 0, entity.as_u64() as i64);
                            push_syscall(&mut code, syscalls::SYSCALL_CORE_QUERY_GET);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::CoreQueryPage {
                            items_dest,
                            next_offset_dest,
                            entity,
                            account,
                            offset,
                            limit,
                        } => {
                            if let Some(account) = account {
                                emit_values_to_syscall_registers(
                                    &[*account, *offset, *limit],
                                    &mut code,
                                )?;
                                code.extend_from_slice(&publish_tlv);
                                push_word(&mut code, encode_addi(13, 10, 0)?);
                            } else {
                                emit_values_to_syscall_registers(&[*offset, *limit], &mut code)?;
                                push_word(&mut code, encode_addi(12, 11, 0)?);
                                push_word(&mut code, encode_addi(11, 10, 0)?);
                                push_word(&mut code, encode_addi(13, 0, 0)?);
                            }
                            emit_addi(&mut code, 10, 0, entity.as_u64() as i64);
                            push_word(&mut code, encode_addi(14, 0, 0)?);
                            push_word(&mut code, encode_addi(15, 0, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_CORE_QUERY_PAGE);
                            // Preserve both syscall results before assigning
                            // allocator-selected destinations: either result
                            // may itself be allocated to r10 or r11.
                            push_word(&mut code, encode_addi(scratch1, 10, 0)?);
                            push_word(&mut code, encode_addi(scratch2, 11, 0)?);
                            let (items_reg, items_spilled, items_imm) = dst_reg(items_dest);
                            push_word(&mut code, encode_addi(items_reg, scratch1, 0)?);
                            spill_back(items_dest, items_reg, items_spilled, items_imm, &mut code)?;
                            let (offset_reg, offset_spilled, offset_imm) =
                                dst_reg(next_offset_dest);
                            push_word(&mut code, encode_addi(offset_reg, scratch2, 0)?);
                            spill_back(
                                next_offset_dest,
                                offset_reg,
                                offset_spilled,
                                offset_imm,
                                &mut code,
                            )?;
                        }
                        Instr::GetAccountBalance {
                            dest,
                            account,
                            asset,
                        } => {
                            load_pointer(account, 10, scratch1, DataKind::Account, &mut code)?;
                            load_pointer(asset, 11, scratch2, DataKind::AssetDef, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_GET_ACCOUNT_BALANCE);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::GetPublicInput { dest, key } => {
                            if dataref_kind_map.get(&(func_idx, *key))
                                == Some(&ir::DataRefKind::Name)
                                && let Some(raw_key) = string_map.get(&(func_idx, *key))
                            {
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    10,
                                    DataKey(DataKind::Name, raw_key.clone()),
                                );
                            } else {
                                let r = src_reg(key, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_GET_PUBLIC_INPUT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::GetPrivateInput { dest, index, kind } => {
                            uses_zk = true;
                            let r = src_reg(index, scratch1, &mut code)?;
                            emit_get_private_input_arguments(&mut code, r, *kind, scratchd)?;
                            push_syscall(&mut code, syscalls::SYSCALL_GET_PRIVATE_INPUT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::CommitOutput => {
                            push_syscall(&mut code, syscalls::SYSCALL_COMMIT_OUTPUT);
                        }
                        Instr::SmartContractLifecycle { payload, syscall } => {
                            load_pointer(payload, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, *syscall);
                        }

                        Instr::ZkRootsGet { dest, payload }
                        | Instr::ZkVoteGetTally { dest, payload } => {
                            load_pointer(payload, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            let syscall = match instr {
                                Instr::ZkRootsGet { .. } => syscalls::SYSCALL_ZK_ROOTS_GET,
                                Instr::ZkVoteGetTally { .. } => syscalls::SYSCALL_ZK_VOTE_GET_TALLY,
                                _ => unreachable!(),
                            };
                            push_syscall(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::VrfEpochSeed { dest, epoch } => {
                            let epoch = src_reg(epoch, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, epoch, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_VRF_EPOCH_SEED);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::SoracloudHostCall {
                            dest,
                            request,
                            syscall,
                        } => {
                            let r = src_reg(request, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, r, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, *syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::SubscriptionBill => {
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_SUBSCRIPTION_BILL);
                        }
                        Instr::SubscriptionRecordUsage => {
                            push_syscall_imm8(
                                &mut code,
                                syscalls::SYSCALL_SUBSCRIPTION_RECORD_USAGE,
                            );
                        }
                        Instr::BuildSubmitBallotInline {
                            dest,
                            election_id,
                            ciphertext,
                            nullifier,
                            backend,
                            proof,
                            vk,
                        } => {
                            use iroha_data_model::{
                                isi::zk as DMZk,
                                proof::{ProofAttachment, ProofBox, VerifyingKeyId},
                            };
                            let require_literal =
                                |label: &str, temp: &ir::Temp| -> Result<String, String> {
                                    if let Some(value) = string_map.get(&(func_idx, *temp)) {
                                        return Ok(value.clone());
                                    }
                                    let err = format!(
                                        "build_submit_ballot_inline requires literal {label}"
                                    );
                                    Err(i18n::translate(self.lang, Message::SemanticError(&err)))
                                };
                            let eid = require_literal("election_id", election_id)?;
                            if !iroha_data_model::governance::is_valid_governance_selector_v1(&eid)
                            {
                                let err = "build_submit_ballot_inline election_id must be 1-128 RFC 3986 unreserved ASCII characters and must not start with a dot"
                                    .to_owned();
                                return Err(i18n::translate(
                                    self.lang,
                                    Message::SemanticError(&err),
                                ));
                            }
                            let backend_str = require_literal("backend", backend)?;
                            let ct_literal = require_literal("ciphertext", ciphertext)?;
                            let ct_bytes = decode_hex_or_raw_bytes(&ct_literal).map_err(|e| {
                                let err =
                                    format!("build_submit_ballot_inline ciphertext literal {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?;
                            let nf_literal = require_literal("nullifier", nullifier)?;
                            let nf_bytes = decode_hex_or_raw_bytes(&nf_literal).map_err(|e| {
                                let err =
                                    format!("build_submit_ballot_inline nullifier literal {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?;
                            if nf_bytes.len() != 32 {
                                let err = "build_submit_ballot_inline nullifier must be 32 bytes"
                                    .to_string();
                                return Err(i18n::translate(
                                    self.lang,
                                    Message::SemanticError(&err),
                                ));
                            }
                            let mut null32 = [0u8; 32];
                            null32.copy_from_slice(&nf_bytes);
                            let proof_literal = require_literal("proof", proof)?;
                            let proof_bytes =
                                decode_hex_or_raw_bytes(&proof_literal).map_err(|e| {
                                    let err =
                                        format!("build_submit_ballot_inline proof literal {e}");
                                    i18n::translate(self.lang, Message::SemanticError(&err))
                                })?;
                            let vk_ref = require_literal("vk_ref", vk)?;
                            let pa = ProofAttachment::new_ref(
                                backend_str.clone(),
                                ProofBox::new(backend_str.clone(), proof_bytes),
                                VerifyingKeyId::new(backend_str, vk_ref),
                            );
                            let sb = DMZk::SubmitBallot {
                                election_id: eid,
                                ciphertext: ct_bytes,
                                ballot_proof: pa,
                                nullifier: null32,
                            };
                            let bytes =
                                ivm_abi::codec::encode_canonical_norito(&InstructionBox::from(sb))
                                    .map_err(|e| {
                                        let err = format!(
                                            "build_submit_ballot_inline encode InstructionBox: {e}"
                                        );
                                        i18n::translate(self.lang, Message::SemanticError(&err))
                                    })?;
                            // Store as NoritoBytes in data and emit load into dest
                            let hex_payload = hex::encode(bytes);
                            let key = DataKey(DataKind::NoritoBytes, hex_payload);
                            let (rd, spilled, imm) = dst_reg(dest);
                            emit_literal_load(&mut code, &fixups, rd, key);
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::RegisterAsset {
                            asset,
                            name,
                            spec,
                            mintable,
                        } => {
                            if let Some(asset_str) = string_map.get(&(func_idx, *asset)) {
                                let key_asset = DataKey(DataKind::AssetDef, asset_str.clone());
                                emit_literal_load(&mut code, &fixups, 10, key_asset);
                            } else {
                                let r_asset = src_reg(asset, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_asset, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            let r_name = src_reg(name, scratch1, &mut code)?;
                            let r_spec = src_reg(spec, scratch2, &mut code)?;
                            let r_mint = src_reg(mintable, scratchd, &mut code)?;
                            push_word(&mut code, encode_addi(11, r_name, 0)?);
                            push_word(&mut code, encode_addi(12, r_spec, 0)?);
                            push_word(&mut code, encode_addi(13, r_mint, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_REGISTER_ASSET);
                        }
                        Instr::TransferAsset {
                            from,
                            to,
                            asset,
                            amount,
                            dataspace,
                        } => {
                            // Pointer-ABI: accept literal pointers (from string_map) or runtime pointers.
                            load_pointer(from, 10, scratch2, DataKind::Account, &mut code)?;
                            load_pointer(to, 11, scratch2, DataKind::Account, &mut code)?;
                            load_pointer(asset, 12, scratch2, DataKind::AssetDef, &mut code)?;
                            if let Some(key) = quantity_literal_data_key(
                                func_idx,
                                *amount,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 13, key);
                            } else {
                                let r_amt = src_reg(amount, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(13, r_amt, 0)?);
                            }
                            load_pointer(
                                dataspace,
                                14,
                                scratch2,
                                DataKind::DataSpaceId,
                                &mut code,
                            )?;
                            // Mirror TLVs for r10, r11, r12, r14 into INPUT.
                            // r10
                            code.extend_from_slice(&publish_tlv);
                            // Preserve the `from` account TLV pointer (x15) before x10 gets reused.
                            push_word(&mut code, encode_addi(15, 10, 0)?);
                            // r11
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            // r12
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            // r13 (amount)
                            push_word(&mut code, encode_addi(10, 13, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(13, 10, 0)?);
                            // r14 (dataspace)
                            push_word(&mut code, encode_addi(10, 14, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(14, 10, 0)?);
                            // Restore `from` pointer into r10 before issuing the syscall
                            push_word(&mut code, encode_addi(10, 15, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_TRANSFER_ASSET_SCOPED);
                        }
                        Instr::TransferBatchAsset {
                            from,
                            to,
                            asset,
                            amount,
                        } => {
                            load_pointer(from, 10, scratch2, DataKind::Account, &mut code)?;
                            load_pointer(to, 11, scratch2, DataKind::Account, &mut code)?;
                            load_pointer(asset, 12, scratch2, DataKind::AssetDef, &mut code)?;
                            if let Some(key) = quantity_literal_data_key(
                                func_idx,
                                *amount,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 13, key);
                            } else {
                                let r_amt = src_reg(amount, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(13, r_amt, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(14, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 13, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(13, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 14, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_TRANSFER_V1);
                        }
                        Instr::EscrowOpenOffer {
                            escrow,
                            asset,
                            amount,
                            evidence_hashes,
                        } => {
                            load_pointer(escrow, 10, scratch2, DataKind::Name, &mut code)?;
                            load_pointer(asset, 11, scratch2, DataKind::AssetDef, &mut code)?;
                            if let Some(key) = quantity_literal_data_key(
                                func_idx,
                                *amount,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 12, key);
                            } else {
                                let r_amount = src_reg(amount, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(12, r_amount, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(14, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            if let Some(evidence_hashes) = evidence_hashes {
                                let r_evidence = src_reg(evidence_hashes, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_evidence, 0)?);
                                code.extend_from_slice(&publish_tlv);
                                push_word(&mut code, encode_addi(13, 10, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(13, 0, 0)?);
                            }
                            push_word(&mut code, encode_addi(10, 14, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_ESCROW_OPEN_OFFER);
                        }
                        Instr::EscrowAccept { escrow }
                        | Instr::EscrowMarkPaymentSent { escrow }
                        | Instr::EscrowRelease { escrow }
                        | Instr::EscrowCancel { escrow } => {
                            load_pointer(escrow, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            let syscall = match instr {
                                Instr::EscrowAccept { .. } => syscalls::SYSCALL_ESCROW_ACCEPT,
                                Instr::EscrowMarkPaymentSent { .. } => {
                                    syscalls::SYSCALL_ESCROW_MARK_PAYMENT_SENT
                                }
                                Instr::EscrowRelease { .. } => syscalls::SYSCALL_ESCROW_RELEASE,
                                Instr::EscrowCancel { .. } => syscalls::SYSCALL_ESCROW_CANCEL,
                                _ => unreachable!(),
                            };
                            push_syscall(&mut code, syscall);
                        }
                        Instr::EscrowOpenDispute {
                            escrow,
                            evidence_hashes,
                        } => {
                            load_pointer(escrow, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            if let Some(evidence_hashes) = evidence_hashes {
                                push_word(&mut code, encode_addi(14, 10, 0)?);
                                let r_evidence = src_reg(evidence_hashes, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_evidence, 0)?);
                                code.extend_from_slice(&publish_tlv);
                                push_word(&mut code, encode_addi(11, 10, 0)?);
                                push_word(&mut code, encode_addi(10, 14, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(11, 0, 0)?);
                            }
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_ESCROW_OPEN_DISPUTE);
                        }
                        Instr::EscrowResolveDispute {
                            escrow,
                            buyer_amount,
                            seller_amount,
                            evidence_hashes,
                        } => {
                            if let Some(key) = quantity_literal_data_key(
                                func_idx,
                                *buyer_amount,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 11, key);
                            } else {
                                let r_buyer = src_reg(buyer_amount, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(11, r_buyer, 0)?);
                            }
                            if let Some(key) = quantity_literal_data_key(
                                func_idx,
                                *seller_amount,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 12, key);
                            } else {
                                let r_seller = src_reg(seller_amount, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(12, r_seller, 0)?);
                            }
                            load_pointer(escrow, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(14, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            if let Some(evidence_hashes) = evidence_hashes {
                                let r_evidence = src_reg(evidence_hashes, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_evidence, 0)?);
                                code.extend_from_slice(&publish_tlv);
                                push_word(&mut code, encode_addi(13, 10, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(13, 0, 0)?);
                            }
                            push_word(&mut code, encode_addi(10, 14, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_ESCROW_RESOLVE_DISPUTE);
                        }
                        Instr::TransferBatchBegin => {
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN);
                        }
                        Instr::TransferBatchEnd => {
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_TRANSFER_V1_BATCH_END);
                        }
                        Instr::CreateNftsForAllUsers => {
                            push_syscall_imm8(
                                &mut code,
                                syscalls::SYSCALL_CREATE_NFTS_FOR_ALL_USERS,
                            );
                        }
                        Instr::SetExecutionDepth { value } => {
                            let r_val = src_reg(value, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, r_val, 0)?);
                            push_syscall_imm8(
                                &mut code,
                                syscalls::SYSCALL_SET_SMARTCONTRACT_EXECUTION_DEPTH,
                            );
                        }
                        Instr::SetVl { value } => {
                            let raw = int_const_map.get(&(func_idx, *value)).copied().ok_or_else(
                                || {
                                    let err =
                                        "setvl expects a literal int in range 0..=255".to_string();
                                    i18n::translate(self.lang, Message::SemanticError(&err))
                                },
                            )?;
                            if !(0..=u8::MAX as i64).contains(&raw) {
                                let err =
                                    format!("setvl value must be in range 0..=255, got {raw}");
                                return Err(i18n::translate(
                                    self.lang,
                                    Message::SemanticError(&err),
                                ));
                            }
                            let word = encoding::wide::encode_rr(
                                instruction::wide::crypto::SETVL,
                                0,
                                0,
                                raw as u8,
                            );
                            code.extend_from_slice(&word.to_le_bytes());
                        }
                        Instr::SetAccountDetail {
                            account,
                            key,
                            value,
                        } => {
                            // Per-argument strategy: values produced via DataRef/StringConst use a
                            // LOAD fixup in the appropriate register; runtime values move from their
                            // allocated register. This allows patterns like
                            // `ledger::account::set_metadata(account: context::authority(),
                            // key: Name::parse("k"), value: Json::parse("{}"))` where only key/value
                            // are literals and account is provided by the host.
                            // r10 = &AccountId
                            load_pointer(account, 10, scratch1, DataKind::Account, &mut code)?;
                            // r11 = &Name
                            load_pointer(key, 11, scratch2, DataKind::Name, &mut code)?;
                            // r12 = &Json
                            load_pointer(value, 12, scratch1, DataKind::Json, &mut code)?;
                            // Mirror all three TLVs into INPUT to satisfy pointer‑ABI validation; preserve registers.
                            // Publish r10
                            code.extend_from_slice(&publish_tlv);
                            // Preserve the account TLV pointer in x13 for the final syscall
                            push_word(&mut code, encode_addi(13, 10, 0)?);
                            // Publish r11: x10 <- x11; publish; x11 <- x10
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            // Publish r12: x10 <- x12; publish; x12 <- x10
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            // Restore account pointer into x10 before issuing the syscall
                            push_word(&mut code, encode_addi(10, 13, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_SET_ACCOUNT_DETAIL);
                        }
                        Instr::CreateNft { nft, owner } => {
                            load_pointer(nft, 10, scratch1, DataKind::NftId, &mut code)?;
                            load_pointer(owner, 11, scratch2, DataKind::Account, &mut code)?;
                            // Mirror TLVs into INPUT for r10 and r11
                            code.extend_from_slice(&publish_tlv); // r10
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_NFT_MINT_ASSET);
                        }
                        Instr::SetNftData { nft, key, json } => {
                            // Load literals or move regs
                            let k_nft = string_map
                                .get(&(func_idx, *nft))
                                .map(|s| DataKey(DataKind::NftId, s.clone()));
                            let k_key = string_map
                                .get(&(func_idx, *key))
                                .map(|s| DataKey(DataKind::Name, s.clone()));
                            let k_json = string_map
                                .get(&(func_idx, *json))
                                .map(|s| DataKey(DataKind::Json, s.clone()));
                            if let Some(kn) = k_nft {
                                emit_literal_load(&mut code, &fixups, 10, kn);
                            } else {
                                let r = src_reg(nft, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            if let Some(kk) = k_key {
                                emit_literal_load(&mut code, &fixups, 11, kk);
                            } else {
                                let r = src_reg(key, scratch2, &mut code)?;
                                push_word(&mut code, encode_addi(11, r, 0)?);
                            }
                            if let Some(kj) = k_json {
                                emit_literal_load(&mut code, &fixups, 12, kj);
                            } else {
                                let r = src_reg(json, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(12, r, 0)?);
                            }
                            // Mirror all pointer arguments into INPUT.
                            code.extend_from_slice(&publish_tlv); // r10
                            push_word(&mut code, encode_addi(scratch1, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch1, 0)?);
                            push_word(&mut code, encode_addi(11, scratch2, 0)?);
                            // SCALL
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_NFT_SET_METADATA);
                        }
                        Instr::BurnNft { nft } => {
                            load_pointer(nft, 10, scratch1, DataKind::NftId, &mut code)?;
                            // Mirror into INPUT
                            code.extend_from_slice(&publish_tlv);
                            // SCALL
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_NFT_BURN_ASSET);
                        }
                        Instr::TransferNft { from, nft, to } => {
                            load_pointer(from, 10, scratch1, DataKind::Account, &mut code)?;
                            load_pointer(nft, 11, scratch2, DataKind::NftId, &mut code)?;
                            load_pointer(to, 12, scratchd, DataKind::Account, &mut code)?;
                            // Mirror TLVs into INPUT for r10, r11, r12
                            code.extend_from_slice(&publish_tlv); // r10
                            push_word(&mut code, encode_addi(13, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 12, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            push_word(&mut code, encode_addi(10, 13, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_NFT_TRANSFER_ASSET);
                        }
                        Instr::DataRef { .. } => {
                            // No code emitted; data is accessed at use sites via fixups.
                        }
                        Instr::GetAuthority { dest } => {
                            // Request host to provide a pointer to the authority AccountId in x10
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_GET_AUTHORITY);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::SysvarAuthority { dest } => {
                            push_syscall(&mut code, syscalls::SYSCALL_SYSVAR_AUTHORITY);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::CurrentTimeMs { dest } => {
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_CURRENT_TIME_MS);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::BlockHeight { dest } => {
                            push_syscall(&mut code, syscalls::SYSCALL_SYSVAR_BLOCK_HEIGHT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::BlockTimeMs { dest } => {
                            push_syscall(&mut code, syscalls::SYSCALL_SYSVAR_BLOCK_TIME_MS);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::ChainId { dest } => {
                            push_syscall(&mut code, syscalls::SYSCALL_SYSVAR_CHAIN_ID);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::ContractAddress { dest } => {
                            push_syscall(&mut code, syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Entrypoint { dest } => {
                            push_syscall(&mut code, syscalls::SYSCALL_SYSVAR_ENTRYPOINT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::ResolveAccountAlias { dest, alias } => {
                            load_pointer(alias, 10, scratch1, DataKind::Blob, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::GetTriggerEvent { dest } => {
                            emit_literal_load(
                                &mut code,
                                &fixups,
                                10,
                                DataKey(DataKind::Name, TRIGGER_EVENT_PUBLIC_INPUT_KEY.to_string()),
                            );
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_GET_PUBLIC_INPUT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::CallContract {
                            dests,
                            contract,
                            binding,
                            payload,
                            argument_words,
                            ..
                        } => {
                            load_pointer(contract, 10, scratch1, DataKind::Blob, &mut code)?;
                            load_pointer(binding, 11, scratch1, DataKind::NoritoBytes, &mut code)?;
                            let table = src_reg(payload, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(12, table, 0)?);
                            emit_i64_literal_load(&mut code, &fixups, 13, *argument_words as i64);
                            emit_bounded_add(
                                &mut code,
                                &fixups,
                                14,
                                sp,
                                frame.outgoing_result_base as i64,
                                LITERAL_SHIFT_REG,
                            )?;
                            emit_i64_literal_load(
                                &mut code,
                                &fixups,
                                15,
                                dests.len().max(1) as i64,
                            );
                            push_syscall(&mut code, syscalls::SYSCALL_CALL_CONTRACT);
                            for (index, destination) in dests.iter().enumerate() {
                                let (rd, spilled, imm) = dst_reg(destination);
                                emit_load64(
                                    &mut code,
                                    &fixups,
                                    rd,
                                    sp,
                                    (frame.outgoing_result_base + index * 8) as i64,
                                    Some(scratch1),
                                )?;
                                spill_back(destination, rd, spilled, imm, &mut code)?;
                            }
                        }
                        Instr::InvokeEntrypointAs {
                            actor,
                            entrypoint,
                            payload,
                            argument_words,
                            ..
                        }
                        | Instr::InvokeEntrypointAsMulti {
                            actor,
                            entrypoint,
                            payload,
                            argument_words,
                            ..
                        } => {
                            let destinations = match instr {
                                Instr::InvokeEntrypointAs { dest, .. } => {
                                    dest.iter().copied().collect::<Vec<_>>()
                                }
                                Instr::InvokeEntrypointAsMulti { dests, .. } => dests.clone(),
                                _ => unreachable!("test invocation selected above"),
                            };
                            let result_words = destinations.len().max(1);
                            if result_words > ivm_abi::call::MAX_CALL_WORDS_V1 {
                                return Err(
                                    "test invocation result table exceeds V1 word limit".into()
                                );
                            }
                            if let Some(actor) = actor {
                                load_pointer(actor, 10, scratch1, DataKind::Blob, &mut code)?;
                            } else {
                                push_word(&mut code, encode_addi(10, 0, 0)?);
                            }
                            load_pointer(entrypoint, 11, scratch1, DataKind::Blob, &mut code)?;
                            let rs_payload = src_reg(payload, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(12, rs_payload, 0)?);
                            emit_i64_literal_load(&mut code, &fixups, 13, *argument_words as i64);
                            emit_bounded_add(
                                &mut code,
                                &fixups,
                                14,
                                sp,
                                frame.outgoing_result_base as i64,
                                LITERAL_SHIFT_REG,
                            )?;
                            emit_i64_literal_load(&mut code, &fixups, 15, result_words as i64);
                            push_syscall(
                                &mut code,
                                syscalls::SYSCALL_KOTO_TEST_INVOKE_ENTRYPOINT_AS,
                            );
                            for (index, destination) in destinations.iter().enumerate() {
                                let (rd, spilled, imm) = dst_reg(destination);
                                emit_load64(
                                    &mut code,
                                    &fixups,
                                    rd,
                                    sp,
                                    (frame.outgoing_result_base + index * 8) as i64,
                                    Some(scratch1),
                                )?;
                                spill_back(destination, rd, spilled, imm, &mut code)?;
                            }
                        }
                        Instr::ExpectRejectAs {
                            actor,
                            entrypoint,
                            payload,
                            argument_words,
                            expectation,
                        } => {
                            load_pointer(actor, 10, scratch1, DataKind::Blob, &mut code)?;
                            load_pointer(entrypoint, 11, scratch1, DataKind::Blob, &mut code)?;
                            let rs_payload = src_reg(payload, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(12, rs_payload, 0)?);
                            emit_i64_literal_load(&mut code, &fixups, 13, *argument_words as i64);
                            load_pointer(expectation, 14, scratch1, DataKind::Blob, &mut code)?;
                            push_word(&mut code, encode_addi(15, 0, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_KOTO_TEST_EXPECT_REJECT_AS);
                        }
                        Instr::ActorAccount { dest, actor } => {
                            load_pointer(actor, 10, scratch1, DataKind::Blob, &mut code)?;
                            push_syscall(&mut code, syscalls::SYSCALL_KOTO_TEST_ACTOR_ACCOUNT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::ActorPublicKey { dest, actor } => {
                            load_pointer(actor, 10, scratch1, DataKind::Blob, &mut code)?;
                            push_syscall(&mut code, syscalls::SYSCALL_KOTO_TEST_ACTOR_PUBLIC_KEY);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::ActorSign {
                            dest,
                            actor,
                            message,
                        } => {
                            load_pointer(actor, 10, scratch1, DataKind::Blob, &mut code)?;
                            if let Some(message_raw) = string_map.get(&(func_idx, *message)) {
                                if let Some(kind) = dataref_kind_map.get(&(func_idx, *message)) {
                                    emit_literal_load(
                                        &mut code,
                                        &fixups,
                                        11,
                                        literal_data_key(message, *kind, message_raw),
                                    );
                                } else {
                                    let rs_message = src_reg(message, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(11, rs_message, 0)?);
                                }
                            } else {
                                let rs_message = src_reg(message, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(11, rs_message, 0)?);
                            }
                            push_syscall(&mut code, syscalls::SYSCALL_KOTO_TEST_ACTOR_SIGN);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Call { callee, args, .. }
                        | Instr::CallMulti { callee, args, .. } => {
                            let signature = signatures
                                .get(callee)
                                .ok_or_else(|| format!("missing call signature for `{callee}`"))?;
                            // Consume every argument before staging descriptor registers. Table
                            // scratch is disjoint from spills and is reused for each loop call.
                            let mut argument_window = StackTableWindow::new(scratchd);
                            for (index, value) in args.iter().enumerate() {
                                let source = if let Some(kind) =
                                    dataref_kind_map.get(&(func_idx, *value)).copied()
                                    && let Some(literal) = string_map.get(&(func_idx, *value))
                                {
                                    emit_literal_load(
                                        &mut code,
                                        &fixups,
                                        scratch1,
                                        literal_data_key(value, kind, literal),
                                    );
                                    scratch1
                                } else {
                                    src_reg(value, scratch1, &mut code)?
                                };
                                let (table_base, table_offset) = argument_window.address(
                                    &mut code,
                                    &fixups,
                                    frame.outgoing_argument_base + index * 8,
                                )?;
                                emit_store64(
                                    &mut code,
                                    &fixups,
                                    table_base,
                                    source,
                                    table_offset,
                                    scratch2,
                                )?;
                            }
                            if args.is_empty() {
                                push_word(&mut code, encode_addi(10, 0, 0)?);
                            } else {
                                emit_bounded_add(
                                    &mut code,
                                    &fixups,
                                    10,
                                    sp,
                                    frame.outgoing_argument_base as i64,
                                    LITERAL_SHIFT_REG,
                                )?;
                            }
                            emit_i64_literal_load(&mut code, &fixups, 11, args.len() as i64);
                            emit_bounded_add(
                                &mut code,
                                &fixups,
                                12,
                                sp,
                                frame.outgoing_result_base as i64,
                                LITERAL_SHIFT_REG,
                            )?;
                            emit_i64_literal_load(
                                &mut code,
                                &fixups,
                                13,
                                signature.result_word_count() as i64,
                            );
                            let at = reserve_word(&mut code);
                            call_fixups.push((at, callee.clone(), func.name.clone()));
                            let destinations = match instr {
                                Instr::Call { dest, .. } => {
                                    dest.iter().copied().collect::<Vec<_>>()
                                }
                                Instr::CallMulti { dests, .. } => dests.clone(),
                                _ => unreachable!("call instruction selected above"),
                            };
                            if !destinations.is_empty()
                                && destinations.len() != signature.result_word_count()
                            {
                                return Err(format!(
                                    "call to `{callee}` has an inconsistent result table"
                                ));
                            }
                            let mut result_window = StackTableWindow::new(scratch1);
                            for (index, destination) in destinations.iter().enumerate() {
                                let (rd, spilled, imm) = dst_reg(destination);
                                let (table_base, table_offset) = result_window.address(
                                    &mut code,
                                    &fixups,
                                    frame.outgoing_result_base + index * 8,
                                )?;
                                emit_load64(
                                    &mut code,
                                    &fixups,
                                    rd,
                                    table_base,
                                    table_offset,
                                    Some(scratch2),
                                )?;
                                spill_back(destination, rd, spilled, imm, &mut code)?;
                            }
                        }
                        Instr::Poseidon6 { dest, args } => {
                            uses_zk = true;
                            // POSEIDON6 consumes one canonical six-register window.
                            // Register allocation treats this instruction as an ABI
                            // clobber, so every operand remains in a preserved home while
                            // this fixed window is staged.
                            let rs_base = regalloc::RET_REG as u8;
                            for (offset, arg) in args.iter().enumerate() {
                                let target = rs_base
                                    + u8::try_from(offset)
                                        .expect("POSEIDON6 register offset fits in u8");
                                let source = src_reg(arg, scratch1, &mut code)?;
                                if source != target {
                                    push_word(&mut code, encode_addi(target, source, 0)?);
                                }
                            }
                            let (rd, spilled, imm) = dst_reg(dest);
                            push_word(&mut code, encoding::wide::encode_poseidon6(rd, rs_base));
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Sm3Hash { dest, message }
                        | Instr::Sha256Hash { dest, message }
                        | Instr::Sha3Hash { dest, message }
                        | Instr::Blake2b256Hash { dest, message }
                        | Instr::Keccak256Hash { dest, message }
                        | Instr::IrohaHash { dest, message } => {
                            load_pointer(message, 10, scratch1, DataKind::Blob, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            let syscall = match instr {
                                Instr::Sm3Hash { .. } => syscalls::SYSCALL_SM3_HASH,
                                Instr::Sha256Hash { .. } => syscalls::SYSCALL_SHA256_HASH,
                                Instr::Sha3Hash { .. } => syscalls::SYSCALL_SHA3_HASH,
                                Instr::Blake2b256Hash { .. } => syscalls::SYSCALL_BLAKE2B256_HASH,
                                Instr::Keccak256Hash { .. } => syscalls::SYSCALL_KECCAK256_HASH,
                                Instr::IrohaHash { .. } => syscalls::SYSCALL_IROHA_HASH,
                                _ => unreachable!(),
                            };
                            push_syscall_imm8(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Sm2Verify {
                            dest,
                            message,
                            signature,
                            public_key,
                            distid,
                        } => {
                            let load_blob_into_x10 =
                                |code: &mut Vec<u8>,
                                 fixups: &LiteralFixups,
                                 temp: &ir::Temp|
                                 -> Result<(), String> {
                                    if let Some(bytes) = string_map.get(&(func_idx, *temp)) {
                                        let key =
                                            literal_data_key(temp, ir::DataRefKind::Blob, bytes);
                                        emit_literal_load(code, fixups, 10, key);
                                    } else {
                                        let rs = src_reg(temp, scratch1, code)?;
                                        push_word(code, encode_addi(10, rs, 0)?);
                                    }
                                    code.extend_from_slice(&publish_tlv);
                                    Ok(())
                                };
                            load_blob_into_x10(&mut code, &fixups, signature)?;
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            load_blob_into_x10(&mut code, &fixups, public_key)?;
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            if let Some(dist) = distid {
                                load_blob_into_x10(&mut code, &fixups, dist)?;
                                push_word(&mut code, encode_addi(13, 10, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(13, 0, 0)?);
                            }
                            load_blob_into_x10(&mut code, &fixups, message)?;
                            let call = encoding::wide::encode_sys(
                                instruction::wide::system::SCALL,
                                syscalls::SYSCALL_SM2_VERIFY as u8,
                            );
                            code.extend_from_slice(&call.to_le_bytes());
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::VerifySignature {
                            dest,
                            message,
                            signature,
                            public_key,
                            scheme,
                        } => {
                            let load_blob_into_x10 =
                                |code: &mut Vec<u8>,
                                 fixups: &LiteralFixups,
                                 temp: &ir::Temp|
                                 -> Result<(), String> {
                                    if let Some(bytes) = string_map.get(&(func_idx, *temp)) {
                                        let key =
                                            literal_data_key(temp, ir::DataRefKind::Blob, bytes);
                                        emit_literal_load(code, fixups, 10, key);
                                    } else {
                                        let rs = src_reg(temp, scratch1, code)?;
                                        push_word(code, encode_addi(10, rs, 0)?);
                                    }
                                    code.extend_from_slice(&publish_tlv);
                                    Ok(())
                                };
                            load_blob_into_x10(&mut code, &fixups, signature)?;
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            load_blob_into_x10(&mut code, &fixups, public_key)?;
                            push_word(&mut code, encode_addi(12, 10, 0)?);
                            let rs = src_reg(scheme, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(13, rs, 0)?);
                            load_blob_into_x10(&mut code, &fixups, message)?;
                            let call = encoding::wide::encode_sys(
                                instruction::wide::system::SCALL,
                                syscalls::SYSCALL_VERIFY_SIGNATURE as u8,
                            );
                            code.extend_from_slice(&call.to_le_bytes());
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Sm4GcmSeal {
                            dest,
                            key,
                            nonce,
                            aad,
                            plaintext,
                        } => {
                            let publish_bytes = publish_tlv;
                            let mut load_blob =
                                |temp: &ir::Temp, target: Option<u8>| -> Result<(), String> {
                                    load_pointer(temp, 10, scratch1, DataKind::Blob, &mut code)?;
                                    code.extend_from_slice(&publish_bytes);
                                    if let Some(rd) = target {
                                        push_word(&mut code, encode_addi(rd, 10, 0)?);
                                    }
                                    Ok(())
                                };
                            load_blob(plaintext, Some(13))?;
                            load_blob(aad, Some(12))?;
                            load_blob(nonce, Some(11))?;
                            load_blob(key, None)?;
                            let call = encoding::wide::encode_sys(
                                instruction::wide::system::SCALL,
                                syscalls::SYSCALL_SM4_GCM_SEAL as u8,
                            );
                            code.extend_from_slice(&call.to_le_bytes());
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Sm4GcmOpen {
                            dest,
                            key,
                            nonce,
                            aad,
                            ciphertext_and_tag,
                        } => {
                            let publish_bytes = publish_tlv;
                            let mut load_blob =
                                |temp: &ir::Temp, target: Option<u8>| -> Result<(), String> {
                                    load_pointer(temp, 10, scratch1, DataKind::Blob, &mut code)?;
                                    code.extend_from_slice(&publish_bytes);
                                    if let Some(rd) = target {
                                        push_word(&mut code, encode_addi(rd, 10, 0)?);
                                    }
                                    Ok(())
                                };
                            load_blob(ciphertext_and_tag, Some(13))?;
                            load_blob(aad, Some(12))?;
                            load_blob(nonce, Some(11))?;
                            load_blob(key, None)?;
                            let call = encoding::wide::encode_sys(
                                instruction::wide::system::SCALL,
                                syscalls::SYSCALL_SM4_GCM_OPEN as u8,
                            );
                            code.extend_from_slice(&call.to_le_bytes());
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Sm4CcmSeal {
                            dest,
                            key,
                            nonce,
                            aad,
                            plaintext,
                            tag_len,
                        } => {
                            let publish_bytes = publish_tlv;
                            let mut load_blob =
                                |temp: &ir::Temp, target: Option<u8>| -> Result<(), String> {
                                    load_pointer(temp, 10, scratch1, DataKind::Blob, &mut code)?;
                                    code.extend_from_slice(&publish_bytes);
                                    if let Some(rd) = target {
                                        push_word(&mut code, encode_addi(rd, 10, 0)?);
                                    }
                                    Ok(())
                                };
                            load_blob(plaintext, Some(13))?;
                            load_blob(aad, Some(12))?;
                            load_blob(nonce, Some(11))?;
                            load_blob(key, None)?;
                            if let Some(tlen) = tag_len {
                                let rs = src_reg(tlen, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(14, rs, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(14, 0, 0)?);
                            }
                            let call = encoding::wide::encode_sys(
                                instruction::wide::system::SCALL,
                                syscalls::SYSCALL_SM4_CCM_SEAL as u8,
                            );
                            code.extend_from_slice(&call.to_le_bytes());
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::Sm4CcmOpen {
                            dest,
                            key,
                            nonce,
                            aad,
                            ciphertext_and_tag,
                            tag_len,
                        } => {
                            let publish_bytes = publish_tlv;
                            let mut load_blob =
                                |temp: &ir::Temp, target: Option<u8>| -> Result<(), String> {
                                    load_pointer(temp, 10, scratch1, DataKind::Blob, &mut code)?;
                                    code.extend_from_slice(&publish_bytes);
                                    if let Some(rd) = target {
                                        push_word(&mut code, encode_addi(rd, 10, 0)?);
                                    }
                                    Ok(())
                                };
                            load_blob(ciphertext_and_tag, Some(13))?;
                            load_blob(aad, Some(12))?;
                            load_blob(nonce, Some(11))?;
                            load_blob(key, None)?;
                            if let Some(tlen) = tag_len {
                                let rs = src_reg(tlen, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(14, rs, 0)?);
                            } else {
                                push_word(&mut code, encode_addi(14, 0, 0)?);
                            }
                            let call = encoding::wide::encode_sys(
                                instruction::wide::system::SCALL,
                                syscalls::SYSCALL_SM4_CCM_OPEN as u8,
                            );
                            code.extend_from_slice(&call.to_le_bytes());
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::AssertEq { left, right } => {
                            let rs1 = src_reg(left, scratch1, &mut code)?;
                            let rs2 = src_reg(right, scratch2, &mut code)?;
                            // Skip ABORT when the values are equal.
                            let skip_word = encode_branch_rv(0x0, rs1, rs2, 8)?;
                            push_word(&mut code, skip_word);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_ABORT);
                        }
                        Instr::Assert { cond } => {
                            let rs = src_reg(cond, scratch1, &mut code)?;
                            // Skip ABORT when the condition is true (i.e., != 0).
                            let skip_word = encode_branch_rv(0x1, rs, 0, 8)?;
                            push_word(&mut code, skip_word);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_ABORT);
                        }
                        Instr::AbortIf {
                            cond,
                            descriptor,
                            code: error_code,
                        } => {
                            let rs = src_reg(cond, scratch1, &mut code)?;
                            let branch_offset = code.len();
                            push_word(&mut code, 0);
                            emit_values_to_syscall_registers(
                                &[*descriptor, *error_code],
                                &mut code,
                            )?;
                            if share_nominal_abort {
                                nominal_abort_sites.push(reserve_word(&mut code));
                            } else {
                                compact_emission::emit_nominal_abort_tail(&mut code)?;
                            }
                            let distance = i16::try_from(code.len() - branch_offset)
                                .map_err(|_| "nominal abort branch exceeds encoding range")?;
                            let branch = encode_branch_rv(0x0, rs, 0, distance)?;
                            code[branch_offset..branch_offset + 4]
                                .copy_from_slice(&branch.to_le_bytes());
                        }
                        Instr::Info { msg } => {
                            let r_msg = src_reg(msg, scratch1, &mut code)?;
                            // Move message to r10 and issue debug log syscall.
                            push_word(&mut code, encode_addi(10, r_msg, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_DEBUG_LOG);
                        }
                        Instr::DebugPrint { value } => {
                            let r_value = src_reg(value, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, r_value, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_DEBUG_PRINT);
                        }
                        Instr::DebugLog { payload } => {
                            if let Some(kind) = dataref_kind_map.get(&(func_idx, *payload))
                                && let Some(raw) = string_map.get(&(func_idx, *payload))
                            {
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    10,
                                    literal_data_key(payload, *kind, raw),
                                );
                            } else {
                                let r_payload = src_reg(payload, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r_payload, 0)?);
                            }
                            push_syscall(&mut code, syscalls::SYSCALL_DEBUG_LOG);
                        }
                        Instr::MapNew { dest } => {
                            let (rd, spilled, imm) = dst_reg(dest);
                            // Request 16 bytes plus alignment slop (8 bytes) in case the heap
                            // baseline is not aligned at 8-byte granularity.
                            emit_addi(&mut code, 10, 0, 24);
                            // SCALL ALLOC
                            let sys = encoding::wide::encode_sys(
                                instruction::wide::system::SCALL,
                                syscalls::SYSCALL_ALLOC as u8,
                            );
                            code.extend_from_slice(&sys.to_le_bytes());
                            // Align x10 to the next 8-byte boundary: x10 = (x10 + 7) & !7
                            emit_addi(&mut code, 10, 10, 7);
                            let andi = encoding::wide::encode_ri(
                                instruction::wide::arithmetic::ANDI,
                                10,
                                10,
                                -8,
                            );
                            code.extend_from_slice(&andi.to_le_bytes());
                            // Zero-initialize the single key/value pair to keep Map::new deterministic.
                            emit_addi(&mut code, scratch1, 0, 0);
                            emit_store64(&mut code, &fixups, 10, scratch1, 0, scratch2)?;
                            emit_store64(&mut code, &fixups, 10, scratch1, 8, scratch2)?;
                            // dest = x10
                            push_word(&mut code, encode_addi(rd, 10, 0)?);
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::PointerFromString { .. } => {
                            // Marker instruction; literal data handled at use-sites via fixups/string_map.
                        }
                        Instr::PointerToNorito { dest, value } => {
                            let pointer_kind = dataref_kind_map.get(&(func_idx, *value)).copied();
                            if let Some(kind) = pointer_kind
                                && let Some(lit) = string_map.get(&(func_idx, *value)).cloned()
                            {
                                let key = literal_data_key(value, kind, &lit);
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                if string_map.contains_key(&(func_idx, *value))
                                    && pointer_kind.is_none()
                                {
                                    return Err(i18n::translate(
                                        self.lang,
                                        Message::SemanticError(
                                            "pointer literal missing ABI metadata during pointer_to_norito lowering",
                                        ),
                                    ));
                                }
                                let rs = src_reg(value, scratch1, &mut code)?;
                                local_emission::emit_move(&mut code, 10, rs)?;
                            }
                            // The existing synchronous consumer validates the original owned
                            // public envelope before reading it; no pointer escapes this call.
                            #[cfg(test)]
                            if state_operands::retain_publication() {
                                code.extend_from_slice(&publish_tlv);
                            }
                            code.extend_from_slice(&pointer_to_bytes);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::PointerFromNorito { dest, blob, kind } => {
                            let type_id = pointer_type_for_kind(*kind).ok_or_else(|| {
                                i18n::translate(
                                    self.lang,
                                    Message::SemanticError(
                                        "unsupported pointer type for pointer_from_norito",
                                    ),
                                )
                            })? as u16;
                            if let Some(bytes) = string_map.get(&(func_idx, *blob)).cloned() {
                                let key = DataKey(DataKind::NoritoBytes, bytes);
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                let rs = src_reg(blob, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, rs, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            emit_addi(&mut code, 11, 0, type_id as i64);
                            code.extend_from_slice(&pointer_from_bytes);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::PointerEq { dest, left, right } => {
                            // Mirror both pointers into INPUT so TLV_EQ validates INPUT-resident TLVs.
                            let load_ptr = |temp: &ir::Temp,
                                            target: u8,
                                            scratch: u8,
                                            code: &mut Vec<u8>|
                             -> Result<(), String> {
                                if let Some(kind) =
                                    dataref_kind_map.get(&(func_idx, *temp)).copied()
                                    && let Some(lit) = string_map.get(&(func_idx, *temp)).cloned()
                                {
                                    let key = literal_data_key(temp, kind, &lit);
                                    emit_literal_load(code, &fixups, target, key);
                                } else {
                                    let rs = src_reg(temp, scratch, code)?;
                                    push_word(code, encode_addi(target, rs, 0)?);
                                }
                                Ok(())
                            };
                            load_ptr(left, 10, scratch1, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            load_ptr(right, 10, scratch2, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_TLV_EQ);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::MapGet { dest, map, key } => {
                            // Minimal map layout: [0..8) key (u64), [8..16) value (u64)
                            // Branchless compare/select via flag multiply:
                            //   flag := SEQ(LOAD64 [map + 0], key)
                            //   dest := LOAD64 [map + 8]
                            //   dest := dest * flag
                            let rmap = src_reg(map, scratch1, &mut code)?;
                            let rkey = src_reg(key, scratch2, &mut code)?;
                            let (rd, spilled, imm) = dst_reg(dest);
                            let mut flag_reg = None;
                            for cand in [scratch1, scratch2, scratchd] {
                                if cand != rmap && cand != rkey && cand != rd {
                                    flag_reg = Some(cand);
                                    break;
                                }
                            }
                            if let Some(rflag) = flag_reg {
                                emit_load64(&mut code, &fixups, rflag, rmap, 0, None)?;
                                let eq = encoding::wide::encode_rr(
                                    instruction::wide::arithmetic::SEQ,
                                    rflag,
                                    rflag,
                                    rkey,
                                );
                                push_word(&mut code, eq);
                                let value_scratch = if rd == rmap {
                                    Some(if rflag != scratch1 {
                                        scratch1
                                    } else {
                                        scratch2
                                    })
                                } else {
                                    None
                                };
                                emit_load64(&mut code, &fixups, rd, rmap, 8, value_scratch)?;
                                push_word(
                                    &mut code,
                                    encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::MUL,
                                        rd,
                                        rd,
                                        rflag,
                                    ),
                                );
                            } else {
                                // Fall back to using rd for the flag and reuse rkey (spilled) for value.
                                emit_load64(&mut code, &fixups, rd, rmap, 0, None)?;
                                let eq = encoding::wide::encode_rr(
                                    instruction::wide::arithmetic::SEQ,
                                    rd,
                                    rd,
                                    rkey,
                                );
                                push_word(&mut code, eq);
                                emit_load64(&mut code, &fixups, rkey, rmap, 8, None)?;
                                push_word(
                                    &mut code,
                                    encoding::wide::encode_rr(
                                        instruction::wide::arithmetic::MUL,
                                        rd,
                                        rkey,
                                        rd,
                                    ),
                                );
                            }
                            spill_back(dest, rd, spilled, imm, &mut code)?;
                        }
                        Instr::Load64Imm { dest, base, imm } => {
                            let rbase = src_reg(base, scratch1, &mut code)?;
                            let (rd, spilled, imm_spill) = dst_reg(dest);
                            let scratch = if rd == rbase {
                                Some(if rd != scratch1 { scratch1 } else { scratch2 })
                            } else {
                                None
                            };
                            emit_load64(&mut code, &fixups, rd, rbase, *imm as i64, scratch)?;
                            spill_back(dest, rd, spilled, imm_spill, &mut code)?;
                        }
                        Instr::Load64 { dest, address } => {
                            let raddress = src_reg(address, scratch1, &mut code)?;
                            let (rd, spilled, imm_spill) = dst_reg(dest);
                            let scratch = if rd == raddress {
                                Some(if rd != scratch1 { scratch1 } else { scratch2 })
                            } else {
                                None
                            };
                            emit_load64(&mut code, &fixups, rd, raddress, 0, scratch)?;
                            spill_back(dest, rd, spilled, imm_spill, &mut code)?;
                        }
                        Instr::Store64Imm { base, imm, value } => {
                            let rbase = src_reg(base, scratch1, &mut code)?;
                            let value_scratch = if rbase != scratch2 {
                                scratch2
                            } else {
                                scratchd
                            };
                            let rvalue = if let Some(kind) =
                                dataref_kind_map.get(&(func_idx, *value)).copied()
                                && let Some(literal) = string_map.get(&(func_idx, *value)).cloned()
                                && !string_literal_temps.contains(&(func_idx, *value))
                            {
                                // DataRef emits no standalone instruction: every
                                // memory use must materialize its literal-table
                                // pointer at that use site. This is required for
                                // bytes/ID literals stored inside Lists and the
                                // native-JSON word table.
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    value_scratch,
                                    literal_data_key(value, kind, &literal),
                                );
                                value_scratch
                            } else {
                                src_reg(value, value_scratch, &mut code)?
                            };
                            let address_scratch = [scratch1, scratch2, scratchd]
                                .into_iter()
                                .find(|candidate| *candidate != rbase && *candidate != rvalue)
                                .ok_or_else(|| {
                                    "no scratch register available for 64-bit list store".to_owned()
                                })?;
                            emit_store64(
                                &mut code,
                                &fixups,
                                rbase,
                                rvalue,
                                i64::from(*imm),
                                address_scratch,
                            )?;
                        }
                        Instr::Store64 { address, value } => {
                            let raddress = src_reg(address, scratch1, &mut code)?;
                            let value_scratch = if raddress != scratch2 {
                                scratch2
                            } else {
                                scratchd
                            };
                            let rvalue = if let Some(kind) =
                                dataref_kind_map.get(&(func_idx, *value)).copied()
                                && let Some(literal) = string_map.get(&(func_idx, *value)).cloned()
                                && !string_literal_temps.contains(&(func_idx, *value))
                            {
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    value_scratch,
                                    literal_data_key(value, kind, &literal),
                                );
                                value_scratch
                            } else {
                                src_reg(value, value_scratch, &mut code)?
                            };
                            let address_scratch = [scratch1, scratch2, scratchd]
                                .into_iter()
                                .find(|candidate| *candidate != raddress && *candidate != rvalue)
                                .ok_or_else(|| {
                                    "no scratch register available for 64-bit list store".to_owned()
                                })?;
                            emit_store64(&mut code, &fixups, raddress, rvalue, 0, address_scratch)?;
                        }
                        Instr::MapSet { map, key, value } => {
                            // Minimal map layout: [0..8) key, [8..16) value
                            let rmap = src_reg(map, scratch1, &mut code)?;
                            let rkey = src_reg(key, scratch2, &mut code)?;
                            let rval = src_reg(value, scratchd, &mut code)?;
                            // Encode 64-bit store of key at offset 0
                            let scratch_base = if rmap != scratch1 { scratch1 } else { scratch2 };
                            emit_store64(&mut code, &fixups, rmap, rkey, 0, scratch_base)?;
                            // Encode 64-bit store of value at offset 8
                            emit_store64(&mut code, &fixups, rmap, rval, 8, scratch_base)?;
                        }
                        Instr::MapLoadPair {
                            dest_key,
                            dest_val,
                            map,
                            offset,
                        } => {
                            // Load key at offset 0, value at offset 8
                            let rmap = src_reg(map, scratch1, &mut code)?;
                            let (rd_k, spilled_k, imm_k) = dst_reg(dest_key);
                            let (rd_v, spilled_v, imm_v) = dst_reg(dest_val);
                            let base_off = *offset as i64; // in bytes
                            let key_scratch = if rd_k == rmap {
                                Some(if rmap != scratch1 { scratch1 } else { scratch2 })
                            } else {
                                None
                            };
                            emit_load64(&mut code, &fixups, rd_k, rmap, base_off, key_scratch)?;
                            spill_back(dest_key, rd_k, spilled_k, imm_k, &mut code)?;
                            let val_scratch = if rd_v == rmap {
                                Some(if rmap != scratch1 { scratch1 } else { scratch2 })
                            } else {
                                None
                            };
                            emit_load64(&mut code, &fixups, rd_v, rmap, base_off + 8, val_scratch)?;
                            spill_back(dest_val, rd_v, spilled_v, imm_v, &mut code)?;
                        }
                        Instr::StateGet { dest, path } => {
                            // Borrow framed StatePath bytes in x10 through the canonical
                            // STATE_GET consumer; move the independently owned result to dest.
                            if let Some(key) = state_path_literal_data_key(
                                func_idx,
                                *path,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                let r = src_reg(path, scratch1, &mut code)?;
                                local_emission::emit_move(&mut code, 10, r)?;
                            }
                            // The existing synchronous consumer validates the original owned
                            // public envelope before reading it; no pointer escapes this call.
                            #[cfg(test)]
                            if state_operands::retain_publication() {
                                code.extend_from_slice(&publish_tlv);
                            }
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_STATE_GET);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::StateSet { path, value } => {
                            // Baseline emission exists only in tests. The production consumer
                            // still validates/copies its owned result or durable value before
                            // returning; borrowing here removes no retaining-boundary clone.
                            #[cfg(test)]
                            if state_operands::retain_publication() {
                                // r10=&NoritoBytes(StatePath); r11=&NoritoBytes value;
                                // publish both to INPUT then SCALL.
                                if let Some(key) = state_path_literal_data_key(
                                    func_idx,
                                    *path,
                                    &string_map,
                                    &dataref_kind_map,
                                )? {
                                    emit_literal_load(&mut code, &fixups, 10, key);
                                } else {
                                    let r = src_reg(path, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(10, r, 0)?);
                                }
                                // Load value into r11
                                load_pointer(
                                    value,
                                    11,
                                    scratch1,
                                    DataKind::NoritoBytes,
                                    &mut code,
                                )?;
                                // Publish both; preserve published path for the final syscall.
                                code.extend_from_slice(&publish_tlv); // r10
                                push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                                push_word(&mut code, encode_addi(10, 11, 0)?);
                                code.extend_from_slice(&publish_tlv);
                                push_word(&mut code, encode_addi(11, 10, 0)?);
                                push_word(&mut code, encode_addi(10, scratch2, 0)?);
                                push_syscall_imm8(&mut code, syscalls::SYSCALL_STATE_SET);
                                continue;
                            }
                            let _ = state_path_literal_data_key(
                                func_idx,
                                *path,
                                &string_map,
                                &dataref_kind_map,
                            )?;
                            emit_syscall_values_with_kinds(
                                &[*path, *value],
                                Some(&[DataKind::NoritoBytes, DataKind::NoritoBytes]),
                                &mut code,
                            )?;
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_STATE_SET);
                        }
                        Instr::StateDel { path } => {
                            // r10=&NoritoBytes(StatePath); publish; SCALL.
                            if let Some(key) = state_path_literal_data_key(
                                func_idx,
                                *path,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                let r = src_reg(path, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_STATE_DEL);
                        }
                        Instr::StateScan {
                            page,
                            next,
                            count,
                            examined,
                            base,
                            after,
                            limit,
                            ..
                        } => {
                            emit_values_to_syscall_registers(&[*base, *after, *limit], &mut code)?;
                            if let Some(key) = state_path_literal_data_key(
                                func_idx,
                                *base,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 10, key);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                            let skip = i16::try_from(publish_tlv.len() + 12)
                                .map_err(|_| "cursor publication branch too large")?;
                            push_word(&mut code, encode_branch_rv(0x0, 11, 0, skip)?);
                            push_word(&mut code, encode_addi(10, 11, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch2, 0)?);
                            for register in 13..=15 {
                                push_word(&mut code, encode_addi(register, 0, 0)?);
                            }
                            push_syscall(&mut code, syscalls::SYSCALL_STATE_SCAN);
                            // Store spilled outputs before parallel register moves so
                            // allocator destinations cannot destroy an unread result.
                            let mut moves = Vec::new();
                            for (index, destination) in
                                [page, next, count, examined].into_iter().enumerate()
                            {
                                let source = 10 + index as u8;
                                let (target, spilled, offset) = dst_reg(destination);
                                if spilled {
                                    emit_store64(&mut code, &fixups, sp, source, offset, scratch2)?;
                                } else if alloc.regs.contains_key(destination) {
                                    moves.push((target, source));
                                }
                            }
                            emit_parallel_register_moves(&mut code, moves, scratch1)?;
                        }
                        Instr::StateMapKeyAt {
                            dest,
                            page,
                            base,
                            index,
                        } => {
                            let page_reg = src_reg(page, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, page_reg, 0)?);
                            load_pointer(base, 11, scratch1, DataKind::Name, &mut code)?;
                            let index_reg = src_reg(index, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(12, index_reg, 0)?);
                            push_syscall(&mut code, syscalls::SYSCALL_STATE_MAP_KEY_AT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::StateValueEncode {
                            dest,
                            schema,
                            words,
                        } => {
                            // Publish a known key as the same canonical record the runtime
                            // encoder produces. This preserves exact static child-key analysis
                            // without adding a second codec or evaluating source operands again.
                            if map_key_encodings.contains(&(func_idx, *dest))
                                && !multiply_defined_dests.contains(&(func_idx, *dest))
                                && let Some(raw) = literal_state_value_record(
                                    func_idx,
                                    *schema,
                                    words,
                                    &string_map,
                                    &dataref_kind_map,
                                    &int_const_map,
                                    &string_literal_temps,
                                )
                            {
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    10,
                                    DataKey(DataKind::NoritoBytes, raw),
                                );
                                spill_syscall_result(dest, &mut code)?;
                            } else {
                                if words.len() > state_value_table_words {
                                    return Err(
                                        "durable aggregate state scratch frame is undersized"
                                            .to_string(),
                                    );
                                }
                                let mut state_window = StackTableWindow::new(scratch1);
                                for (index, word) in words.iter().enumerate() {
                                    let source = if let Some(kind) =
                                        dataref_kind_map.get(&(func_idx, *word)).copied()
                                        && let Some(literal) =
                                            string_map.get(&(func_idx, *word)).cloned()
                                    {
                                        emit_literal_load(
                                            &mut code,
                                            &fixups,
                                            scratch2,
                                            literal_data_key(word, kind, &literal),
                                        );
                                        scratch2
                                    } else {
                                        src_reg(word, scratch2, &mut code)?
                                    };
                                    let offset = state_value_table_base
                                        .checked_add(index.saturating_mul(
                                            ivm_abi::state_value::DECODED_STATE_VALUE_WORD_BYTES
                                                as usize,
                                        ))
                                        .ok_or_else(|| {
                                            "durable aggregate state table offset overflow"
                                                .to_string()
                                        })?;
                                    let (table_base, table_offset) =
                                        state_window.address(&mut code, &fixups, offset)?;
                                    emit_store64(
                                        &mut code,
                                        &fixups,
                                        table_base,
                                        source,
                                        table_offset,
                                        scratchd,
                                    )?;
                                }
                                if let Some(kind) =
                                    dataref_kind_map.get(&(func_idx, *schema)).copied()
                                    && let Some(literal) =
                                        string_map.get(&(func_idx, *schema)).cloned()
                                {
                                    emit_literal_load(
                                        &mut code,
                                        &fixups,
                                        10,
                                        literal_data_key(schema, kind, &literal),
                                    );
                                } else {
                                    let schema_reg = src_reg(schema, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(10, schema_reg, 0)?);
                                }
                                emit_bounded_add(
                                    &mut code,
                                    &fixups,
                                    11,
                                    sp,
                                    state_value_table_base as i64,
                                    LITERAL_SHIFT_REG,
                                )?;
                                emit_addi(&mut code, 12, 0, words.len() as i64);
                                push_syscall(&mut code, syscalls::SYSCALL_STATE_VALUE_ENCODE);
                                spill_syscall_result(dest, &mut code)?;
                            }
                        }
                        Instr::StateHas { dest, path } => {
                            if let Some(key) = state_path_literal_data_key(
                                func_idx,
                                *path,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                let r = src_reg(path, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_STATE_HAS);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::StateLen { dest, path } => {
                            if let Some(key) = state_path_literal_data_key(
                                func_idx,
                                *path,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                let r = src_reg(path, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_STATE_LEN);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::StateCount { dest, prefix } => {
                            if let Some(key) = state_path_literal_data_key(
                                func_idx,
                                *prefix,
                                &string_map,
                                &dataref_kind_map,
                            )? {
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                let r = src_reg(prefix, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_STATE_COUNT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::IntFromI64 { dest, value } | Instr::IntFromU64 { dest, value } => {
                            let rv = src_reg(value, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, rv, 0)?);
                            let syscall = match instr {
                                Instr::IntFromI64 { .. } => syscalls::SYSCALL_INT_FROM_I64,
                                Instr::IntFromU64 { .. } => syscalls::SYSCALL_INT_FROM_U64,
                                _ => unreachable!("matched scalar-to-int conversions"),
                            };
                            push_syscall(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::IntToI64 { dest, value } | Instr::IntToU64 { dest, value } => {
                            load_pointer(value, 10, scratch1, DataKind::Int, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            let syscall = match instr {
                                Instr::IntToI64 { .. } => syscalls::SYSCALL_INT_TO_I64,
                                Instr::IntToU64 { .. } => syscalls::SYSCALL_INT_TO_U64,
                                _ => unreachable!("matched int-to-scalar conversions"),
                            };
                            // Scalar-only host boundaries preserve the exact numeric fault.
                            // Reserved operands and the trap failure mode are all zero.
                            for register in 11..=14 {
                                push_word(&mut code, encode_addi(register, 0, 0)?);
                            }
                            push_syscall(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::NumericConvert {
                            dest,
                            value,
                            source,
                            destination,
                        } => {
                            if let Some(s) = string_map.get(&(func_idx, *value)) {
                                let data_kind = match source {
                                    ir::WideNumericKind::Int => DataKind::Int,
                                    ir::WideNumericKind::Decimal => DataKind::Decimal,
                                    ir::WideNumericKind::Quantity => DataKind::Quantity,
                                };
                                let key = DataKey(data_kind, s.clone());
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                let r = src_reg(value, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            let syscall = match (source, destination) {
                                (ir::WideNumericKind::Int, ir::WideNumericKind::Decimal) => {
                                    syscalls::SYSCALL_DECIMAL_FROM_INT
                                }
                                (ir::WideNumericKind::Int, ir::WideNumericKind::Quantity) => {
                                    syscalls::SYSCALL_QUANTITY_FROM_INT
                                }
                                (ir::WideNumericKind::Decimal, ir::WideNumericKind::Int) => {
                                    syscalls::SYSCALL_DECIMAL_TO_INT_EXACT
                                }
                                (ir::WideNumericKind::Decimal, ir::WideNumericKind::Quantity) => {
                                    syscalls::SYSCALL_QUANTITY_FROM_DECIMAL
                                }
                                (ir::WideNumericKind::Quantity, ir::WideNumericKind::Decimal) => {
                                    syscalls::SYSCALL_QUANTITY_TO_DECIMAL
                                }
                                _ => {
                                    return Err(
                                        "unsupported Kotodama numeric conversion".to_owned()
                                    );
                                }
                            };
                            for register in 11..=14 {
                                push_word(&mut code, encode_addi(register, 0, 0)?);
                            }
                            push_syscall(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::NumericTryConvert {
                            dest,
                            value,
                            source,
                            destination,
                        } => {
                            if let Some(s) = string_map.get(&(func_idx, *value)) {
                                let data_kind = match source {
                                    ir::WideNumericKind::Int => DataKind::Int,
                                    ir::WideNumericKind::Decimal => DataKind::Decimal,
                                    ir::WideNumericKind::Quantity => DataKind::Quantity,
                                };
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    10,
                                    DataKey(data_kind, s.clone()),
                                );
                            } else {
                                let r = src_reg(value, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            let syscall = match (source, destination) {
                                (ir::WideNumericKind::Int, ir::WideNumericKind::Quantity) => {
                                    syscalls::SYSCALL_QUANTITY_FROM_INT
                                }
                                (ir::WideNumericKind::Decimal, ir::WideNumericKind::Quantity) => {
                                    syscalls::SYSCALL_QUANTITY_FROM_DECIMAL
                                }
                                _ => {
                                    return Err(
                                        "unsupported recoverable Kotodama numeric conversion"
                                            .to_owned(),
                                    );
                                }
                            };
                            for register in 11..=13 {
                                push_word(&mut code, encode_addi(register, 0, 0)?);
                            }
                            push_word(
                                &mut code,
                                encode_addi(
                                    ivm_abi::numeric::NUMERIC_FAILURE_MODE_REGISTER as u8,
                                    0,
                                    ivm_abi::numeric::NUMERIC_FAILURE_STATUS as i16,
                                )?,
                            );
                            push_syscall(&mut code, syscall);
                            let (result_reg, result_spilled, result_imm) = dst_reg(dest);
                            push_word(&mut code, encode_addi(result_reg, 10, 0)?);
                            spill_back(dest, result_reg, result_spilled, result_imm, &mut code)?;
                        }
                        Instr::NumericStatus { dest } => {
                            let (status_reg, status_spilled, status_imm) = dst_reg(dest);
                            push_word(&mut code, encode_addi(status_reg, 11, 0)?);
                            spill_back(dest, status_reg, status_spilled, status_imm, &mut code)?;
                        }
                        Instr::NumericNeg { dest, value, kind } => {
                            if let Some(kind) = dataref_kind_map.get(&(func_idx, *value)).copied()
                                && let Some(lit) = string_map.get(&(func_idx, *value)).cloned()
                            {
                                let key = literal_data_key(value, kind, &lit);
                                emit_literal_load(&mut code, &fixups, 10, key);
                            } else {
                                if string_map.contains_key(&(func_idx, *value))
                                    && !dataref_kind_map.contains_key(&(func_idx, *value))
                                {
                                    return Err(i18n::translate(
                                        self.lang,
                                        Message::SemanticError(
                                            "numeric literal missing ABI metadata during numeric lowering",
                                        ),
                                    ));
                                }
                                let r = src_reg(value, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            for register in 11..=14 {
                                push_word(&mut code, encode_addi(register, 0, 0)?);
                            }
                            let syscall = match kind {
                                ir::WideNumericKind::Int => syscalls::SYSCALL_INT_NEG,
                                ir::WideNumericKind::Decimal => syscalls::SYSCALL_DECIMAL_NEG,
                                ir::WideNumericKind::Quantity => {
                                    return Err(
                                        "quantity negation reached code generation".to_owned()
                                    );
                                }
                            };
                            push_syscall(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::NumericBinary {
                            dest,
                            op,
                            left,
                            right,
                            left_kind,
                            right_kind,
                            result_kind,
                        } => {
                            emit_numeric_operands(left, right, &mut code)?;
                            numeric_zero.emit_trap_inputs(&mut code, &fixups)?;
                            let num = match (left_kind, op, right_kind, result_kind) {
                                (
                                    ir::WideNumericKind::Int,
                                    BinaryOp::Add,
                                    ir::WideNumericKind::Int,
                                    ir::WideNumericKind::Int,
                                ) => syscalls::SYSCALL_INT_ADD,
                                (
                                    ir::WideNumericKind::Int,
                                    BinaryOp::Sub,
                                    ir::WideNumericKind::Int,
                                    ir::WideNumericKind::Int,
                                ) => syscalls::SYSCALL_INT_SUB,
                                (
                                    ir::WideNumericKind::Int,
                                    BinaryOp::Mul,
                                    ir::WideNumericKind::Int,
                                    ir::WideNumericKind::Int,
                                ) => syscalls::SYSCALL_INT_MUL,
                                (
                                    ir::WideNumericKind::Int,
                                    BinaryOp::Div,
                                    ir::WideNumericKind::Int,
                                    ir::WideNumericKind::Int,
                                ) => syscalls::SYSCALL_INT_DIV,
                                (
                                    ir::WideNumericKind::Int,
                                    BinaryOp::Mod,
                                    ir::WideNumericKind::Int,
                                    ir::WideNumericKind::Int,
                                ) => syscalls::SYSCALL_INT_REM,
                                (
                                    ir::WideNumericKind::Decimal,
                                    BinaryOp::Add,
                                    ir::WideNumericKind::Decimal,
                                    ir::WideNumericKind::Decimal,
                                ) => syscalls::SYSCALL_DECIMAL_ADD,
                                (
                                    ir::WideNumericKind::Decimal,
                                    BinaryOp::Sub,
                                    ir::WideNumericKind::Decimal,
                                    ir::WideNumericKind::Decimal,
                                ) => syscalls::SYSCALL_DECIMAL_SUB,
                                (
                                    ir::WideNumericKind::Decimal,
                                    BinaryOp::Mul,
                                    ir::WideNumericKind::Decimal,
                                    ir::WideNumericKind::Decimal,
                                ) => syscalls::SYSCALL_DECIMAL_MUL,
                                (
                                    ir::WideNumericKind::Decimal,
                                    BinaryOp::Div,
                                    ir::WideNumericKind::Decimal,
                                    ir::WideNumericKind::Decimal,
                                ) => syscalls::SYSCALL_DECIMAL_DIV_EXACT,
                                (
                                    ir::WideNumericKind::Quantity,
                                    BinaryOp::Add,
                                    ir::WideNumericKind::Quantity,
                                    ir::WideNumericKind::Quantity,
                                ) => syscalls::SYSCALL_QUANTITY_ADD,
                                (
                                    ir::WideNumericKind::Quantity,
                                    BinaryOp::Sub,
                                    ir::WideNumericKind::Quantity,
                                    ir::WideNumericKind::Quantity,
                                ) => syscalls::SYSCALL_QUANTITY_SUB,
                                (
                                    ir::WideNumericKind::Quantity,
                                    BinaryOp::Mul,
                                    ir::WideNumericKind::Decimal,
                                    ir::WideNumericKind::Quantity,
                                ) => syscalls::SYSCALL_QUANTITY_MUL_DECIMAL,
                                (
                                    ir::WideNumericKind::Quantity,
                                    BinaryOp::Div,
                                    ir::WideNumericKind::Decimal,
                                    ir::WideNumericKind::Quantity,
                                ) => syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT,
                                (
                                    ir::WideNumericKind::Quantity,
                                    BinaryOp::Div,
                                    ir::WideNumericKind::Quantity,
                                    ir::WideNumericKind::Decimal,
                                ) => syscalls::SYSCALL_QUANTITY_RATIO_EXACT,
                                _ => {
                                    return Err(i18n::translate(
                                        self.lang,
                                        Message::SemanticError(
                                            "numeric binary operands do not match the V1 operator matrix",
                                        ),
                                    ));
                                }
                            };
                            push_syscall(&mut code, num);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::NumericRound {
                            dest,
                            dividend,
                            multiplier,
                            divisor,
                            scale,
                            mode,
                            op,
                            ..
                        } => {
                            if let Some(multiplier) = multiplier {
                                emit_values_to_syscall_registers(
                                    &[*dividend, *multiplier, *divisor, *scale, *mode],
                                    &mut code,
                                )?;
                                #[cfg(test)]
                                if compact_emission::retain_scalar() {
                                    code.extend_from_slice(&publish_tlv);
                                    push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                                    for register in 11..=13 {
                                        push_word(&mut code, encode_addi(10, register, 0)?);
                                        code.extend_from_slice(&publish_tlv);
                                        push_word(&mut code, encode_addi(register, 10, 0)?);
                                    }
                                    push_word(&mut code, encode_addi(10, scratch2, 0)?);
                                }
                                // The original numeric consumer snapshots, authenticates and
                                // meters each owned public envelope, including the scale Int.
                                push_word(&mut code, encode_addi(15, 0, 0)?);
                                let syscall = match op {
                                    ir::NumericRoundOp::DecimalMulDiv => {
                                        syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND
                                    }
                                    ir::NumericRoundOp::QuantityMulDiv => {
                                        syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND
                                    }
                                    _ => {
                                        return Err(
                                            "non-fused operation carries a multiplier".into()
                                        );
                                    }
                                };
                                push_syscall(&mut code, syscall);
                                spill_syscall_result(dest, &mut code)?;
                            } else {
                                #[cfg(test)]
                                let scalar_arguments = if compact_emission::retain_scalar() {
                                    let load_ptr =
                                        |temp: &ir::Temp,
                                         target: u8,
                                         scratch: u8,
                                         code: &mut Vec<u8>|
                                         -> Result<(), String> {
                                            if let Some(kind) =
                                                dataref_kind_map.get(&(func_idx, *temp)).copied()
                                                && let Some(lit) =
                                                    string_map.get(&(func_idx, *temp)).cloned()
                                            {
                                                emit_literal_load(
                                                    code,
                                                    &fixups,
                                                    target,
                                                    literal_data_key(temp, kind, &lit),
                                                );
                                            } else {
                                                let rs = src_reg(temp, scratch, code)?;
                                                push_word(code, encode_addi(target, rs, 0)?);
                                            }
                                            Ok(())
                                        };
                                    load_ptr(dividend, 10, scratch1, &mut code)?;
                                    code.extend_from_slice(&publish_tlv);
                                    push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                                    load_ptr(divisor, 10, scratch1, &mut code)?;
                                    code.extend_from_slice(&publish_tlv);
                                    push_word(&mut code, encode_addi(11, 10, 0)?);
                                    load_ptr(scale, 10, scratch1, &mut code)?;
                                    code.extend_from_slice(&publish_tlv);
                                    push_word(&mut code, encode_addi(12, 10, 0)?);
                                    push_word(&mut code, encode_addi(10, scratch2, 0)?);
                                    let rounding = src_reg(mode, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(13, rounding, 0)?);
                                    true
                                } else {
                                    false
                                };
                                #[cfg(not(test))]
                                let scalar_arguments = false;
                                if !scalar_arguments {
                                    emit_values_to_syscall_registers(
                                        &[*dividend, *divisor, *scale, *mode],
                                        &mut code,
                                    )?;
                                }
                                push_word(&mut code, encode_addi(14, 0, 0)?);
                                let syscall = match op {
                                    ir::NumericRoundOp::DecimalMulDiv
                                    | ir::NumericRoundOp::QuantityMulDiv => {
                                        return Err(
                                            "fused operation is missing its multiplier".into()
                                        );
                                    }
                                    ir::NumericRoundOp::DecimalDiv => {
                                        syscalls::SYSCALL_DECIMAL_DIV_ROUND
                                    }
                                    ir::NumericRoundOp::QuantityDiv => {
                                        syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND
                                    }
                                    ir::NumericRoundOp::QuantityRatio => {
                                        syscalls::SYSCALL_QUANTITY_RATIO_ROUND
                                    }
                                };
                                push_syscall(&mut code, syscall);
                                spill_syscall_result(dest, &mut code)?;
                            }
                        }
                        Instr::DecimalToInt {
                            dest,
                            value,
                            mode,
                            op,
                        } => {
                            load_pointer(value, 10, scratch1, DataKind::Decimal, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 0, 0)?);
                            push_word(&mut code, encode_addi(12, 0, 0)?);
                            match (op, mode) {
                                (ir::DecimalToIntOp::Truncate, None) => {
                                    push_word(&mut code, encode_addi(13, 0, 0)?);
                                }
                                (ir::DecimalToIntOp::Round, Some(mode)) => {
                                    let rounding = src_reg(mode, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(13, rounding, 0)?);
                                }
                                _ => {
                                    return Err(
                                        "malformed decimal-to-int conversion reached codegen"
                                            .to_owned(),
                                    );
                                }
                            }
                            push_word(&mut code, encode_addi(14, 0, 0)?);
                            push_syscall(
                                &mut code,
                                match op {
                                    ir::DecimalToIntOp::Truncate => {
                                        syscalls::SYSCALL_DECIMAL_TO_INT_TRUNC
                                    }
                                    ir::DecimalToIntOp::Round => {
                                        syscalls::SYSCALL_DECIMAL_TO_INT_ROUND
                                    }
                                },
                            );
                            push_word(&mut code, encode_branch_rv(0x0, 11, 0, 8)?);
                            push_syscall(&mut code, syscalls::SYSCALL_ABORT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::NumericCompare {
                            dest,
                            op,
                            left,
                            right,
                            kind,
                        } => {
                            emit_numeric_operands(left, right, &mut code)?;
                            let num = match (kind, op) {
                                (ir::WideNumericKind::Int, BinaryOp::Eq) => {
                                    syscalls::SYSCALL_INT_EQ
                                }
                                (ir::WideNumericKind::Int, BinaryOp::Ne) => {
                                    syscalls::SYSCALL_INT_NE
                                }
                                (ir::WideNumericKind::Int, BinaryOp::Lt) => {
                                    syscalls::SYSCALL_INT_LT
                                }
                                (ir::WideNumericKind::Int, BinaryOp::Le) => {
                                    syscalls::SYSCALL_INT_LE
                                }
                                (ir::WideNumericKind::Int, BinaryOp::Gt) => {
                                    syscalls::SYSCALL_INT_GT
                                }
                                (ir::WideNumericKind::Int, BinaryOp::Ge) => {
                                    syscalls::SYSCALL_INT_GE
                                }
                                (ir::WideNumericKind::Decimal, BinaryOp::Eq) => {
                                    syscalls::SYSCALL_DECIMAL_EQ
                                }
                                (ir::WideNumericKind::Decimal, BinaryOp::Ne) => {
                                    syscalls::SYSCALL_DECIMAL_NE
                                }
                                (ir::WideNumericKind::Decimal, BinaryOp::Lt) => {
                                    syscalls::SYSCALL_DECIMAL_LT
                                }
                                (ir::WideNumericKind::Decimal, BinaryOp::Le) => {
                                    syscalls::SYSCALL_DECIMAL_LE
                                }
                                (ir::WideNumericKind::Decimal, BinaryOp::Gt) => {
                                    syscalls::SYSCALL_DECIMAL_GT
                                }
                                (ir::WideNumericKind::Decimal, BinaryOp::Ge) => {
                                    syscalls::SYSCALL_DECIMAL_GE
                                }
                                (ir::WideNumericKind::Quantity, BinaryOp::Eq) => {
                                    syscalls::SYSCALL_QUANTITY_EQ
                                }
                                (ir::WideNumericKind::Quantity, BinaryOp::Ne) => {
                                    syscalls::SYSCALL_QUANTITY_NE
                                }
                                (ir::WideNumericKind::Quantity, BinaryOp::Lt) => {
                                    syscalls::SYSCALL_QUANTITY_LT
                                }
                                (ir::WideNumericKind::Quantity, BinaryOp::Le) => {
                                    syscalls::SYSCALL_QUANTITY_LE
                                }
                                (ir::WideNumericKind::Quantity, BinaryOp::Gt) => {
                                    syscalls::SYSCALL_QUANTITY_GT
                                }
                                (ir::WideNumericKind::Quantity, BinaryOp::Ge) => {
                                    syscalls::SYSCALL_QUANTITY_GE
                                }
                                _ => {
                                    return Err(i18n::translate(
                                        self.lang,
                                        Message::SemanticError(
                                            "numeric compare expects comparison operator",
                                        ),
                                    ));
                                }
                            };
                            push_syscall(&mut code, num);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::DirectHelperSyscall {
                            dest,
                            syscall,
                            args,
                        } => {
                            // Typed integer helpers use the existing synchronous metered
                            // snapshots. Stage every register source in parallel before
                            // materializing literals/spills; no pointer survives the call.
                            if matches!(
                                *syscall,
                                syscalls::SYSCALL_INT_ISQRT..=syscalls::SYSCALL_INT_MEAN
                            ) {
                                #[cfg(test)]
                                let scalar_arguments = if compact_emission::retain_scalar() {
                                    for (index, arg) in args.iter().enumerate() {
                                        if let Some(kind) =
                                            dataref_kind_map.get(&(func_idx, *arg)).copied()
                                            && let Some(lit) =
                                                string_map.get(&(func_idx, *arg)).cloned()
                                        {
                                            emit_literal_load(
                                                &mut code,
                                                &fixups,
                                                10,
                                                literal_data_key(arg, kind, &lit),
                                            );
                                        } else {
                                            let source = src_reg(arg, scratch1, &mut code)?;
                                            push_word(&mut code, encode_addi(10, source, 0)?);
                                        }
                                        code.extend_from_slice(&publish_tlv);
                                        if index == 0 && args.len() == 2 {
                                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                                        } else if index == 1 {
                                            push_word(&mut code, encode_addi(11, 10, 0)?);
                                            push_word(&mut code, encode_addi(10, scratch2, 0)?);
                                        }
                                    }
                                    true
                                } else {
                                    false
                                };
                                #[cfg(not(test))]
                                let scalar_arguments = false;
                                if !scalar_arguments {
                                    emit_values_to_syscall_registers(args, &mut code)?;
                                }
                                for register in (10 + args.len() as u8)..=14 {
                                    push_word(&mut code, encode_addi(register, 0, 0)?);
                                }
                                push_syscall(&mut code, *syscall);
                                spill_syscall_result(dest, &mut code)?;
                            } else {
                                if local_emission::parallel_state_decode(*syscall, args.len())
                                    || matches!(
                                        *syscall,
                                        syscalls::SYSCALL_VALUE_ENCODE
                                            | syscalls::SYSCALL_VALUE_TO_STRING
                                            | syscalls::SYSCALL_BLOB_CONCAT
                                            | syscalls::SYSCALL_UTF8_VALIDATE
                                    )
                                {
                                    // The original schema/data decoder consumes its owned
                                    // canonical inputs after every register source is staged.
                                    emit_values_to_syscall_registers(args, &mut code)?;
                                } else {
                                    for (idx, arg) in args.iter().enumerate() {
                                        let target = 10u8.checked_add(idx as u8).ok_or_else(|| {
                                        i18n::translate(
                                            self.lang,
                                            Message::SemanticError(
                                                "direct helper syscall has too many arguments",
                                            ),
                                        )
                                    })?;
                                        if let Some(kind) =
                                            dataref_kind_map.get(&(func_idx, *arg)).copied()
                                            && let Some(lit) =
                                                string_map.get(&(func_idx, *arg)).cloned()
                                        {
                                            let key = literal_data_key(arg, kind, &lit);
                                            emit_literal_load(&mut code, &fixups, target, key);
                                        } else {
                                            let scratch = if target == scratch1 {
                                                scratch2
                                            } else {
                                                scratch1
                                            };
                                            let r = src_reg(arg, scratch, &mut code)?;
                                            push_word(&mut code, encode_addi(target, r, 0)?);
                                        }
                                    }
                                }
                                push_syscall(&mut code, *syscall);
                                spill_syscall_result(dest, &mut code)?;
                            }
                        }
                        Instr::StatePathFromName { dest, name } => {
                            // r10=&Name; publish; SCALL STATE_PATH_FROM_NAME;
                            // r10=&NoritoBytes(StatePath).
                            if let Some(s) = string_map.get(&(func_idx, *name)) {
                                let kind = dataref_kind_map.get(&(func_idx, *name));
                                if kind != Some(&ir::DataRefKind::Name) {
                                    return Err(format!(
                                        "StatePath conversion received compiler literal `{s}` with pointer kind {kind:?}; expected Name"
                                    ));
                                }
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    10,
                                    DataKey(DataKind::Name, s.clone()),
                                );
                            } else {
                                let source = src_reg(name, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, source, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_STATE_PATH_FROM_NAME);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::PathMapKeyNorito {
                            dest,
                            base,
                            key_blob,
                        } => {
                            // Baseline emission exists only in tests. The production consumer
                            // still validates/copies its owned result or durable value before
                            // returning; borrowing here removes no retaining-boundary clone.
                            #[cfg(test)]
                            if state_operands::retain_publication() {
                                // r10=&Name base; publish; r11=&NoritoBytes blob; publish;
                                // SCALL BUILD_PATH_KEY_NORITO -> &NoritoBytes(StatePath).
                                if let Some(s) = string_map.get(&(func_idx, *base)) {
                                    let kb = DataKey(DataKind::Name, s.clone());
                                    emit_literal_load(&mut code, &fixups, 10, kb);
                                } else {
                                    let r = src_reg(base, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(10, r, 0)?);
                                }
                                code.extend_from_slice(&publish_tlv);
                                if let Some(s) = string_map.get(&(func_idx, *key_blob)) {
                                    let kb = DataKey(DataKind::NoritoBytes, s.clone());
                                    emit_literal_load(&mut code, &fixups, 11, kb);
                                } else {
                                    let r = src_reg(key_blob, scratch1, &mut code)?;
                                    push_word(&mut code, encode_addi(11, r, 0)?);
                                }
                                // INPUT_PUBLISH_TLV always operates on r10, so preserve the published
                                // base pointer while mirroring the key blob through r10.
                                push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                                push_word(&mut code, encode_addi(10, 11, 0)?);
                                code.extend_from_slice(&publish_tlv);
                                push_word(&mut code, encode_addi(11, 10, 0)?);
                                push_word(&mut code, encode_addi(10, scratch2, 0)?);
                                push_syscall_imm8(
                                    &mut code,
                                    syscalls::SYSCALL_BUILD_PATH_KEY_NORITO,
                                );
                                spill_syscall_result(dest, &mut code)?;
                                continue;
                            }
                            emit_syscall_values_with_kinds(
                                &[*base, *key_blob],
                                Some(&[DataKind::Name, DataKind::NoritoBytes]),
                                &mut code,
                            )?;
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_BUILD_PATH_KEY_NORITO);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::JsonEncode { dest, json } => {
                            // r10=&Json; publish; SCALL JSON_ENCODE; move r10
                            load_pointer(json, 10, scratch1, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_JSON_ENCODE);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::JsonDecode { dest, blob } => {
                            // r10=&NoritoBytes or &Blob; publish; SCALL JSON_DECODE; move
                            load_pointer(blob, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_JSON_DECODE);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::JsonObject { dest } => {
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_JSON_OBJECT);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::JsonSetInt {
                            dest,
                            json,
                            key,
                            value,
                        } => {
                            load_pointer(json, 10, scratch1, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                            if let Some(s) = string_map.get(&(func_idx, *key)) {
                                let kb = DataKey(DataKind::Name, s.clone());
                                emit_literal_load(&mut code, &fixups, 10, kb);
                            } else {
                                let r = src_reg(key, scratch1, &mut code)?;
                                push_word(&mut code, encode_addi(10, r, 0)?);
                            }
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch2, 0)?);
                            let value_reg = src_reg(value, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(12, value_reg, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_JSON_SET_I64);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::JsonSetAccountId {
                            dest,
                            json,
                            key,
                            value,
                        } => {
                            let load_ptr = |temp: &ir::Temp,
                                            target: u8,
                                            scratch: u8,
                                            code: &mut Vec<u8>|
                             -> Result<(), String> {
                                if let Some(kind) =
                                    dataref_kind_map.get(&(func_idx, *temp)).copied()
                                    && let Some(lit) = string_map.get(&(func_idx, *temp)).cloned()
                                {
                                    let key = literal_data_key(temp, kind, &lit);
                                    emit_literal_load(code, &fixups, target, key);
                                } else {
                                    if string_map.contains_key(&(func_idx, *temp))
                                        && !dataref_kind_map.contains_key(&(func_idx, *temp))
                                    {
                                        return Err(i18n::translate(
                                            self.lang,
                                            Message::SemanticError(
                                                "pointer literal missing ABI metadata during json_set_account_id lowering",
                                            ),
                                        ));
                                    }
                                    let rs = src_reg(temp, scratch, code)?;
                                    push_word(code, encode_addi(target, rs, 0)?);
                                }
                                Ok(())
                            };
                            load_ptr(json, 10, scratch1, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                            load_ptr(key, 10, scratch1, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch2, 0)?);
                            load_ptr(value, 12, scratch1, &mut code)?;
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_JSON_SET_ACCOUNT_ID);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::TlvLen { dest, value } => {
                            // r10=&TLV; publish; SCALL TLV_LEN; move r10 (len) to dest
                            let r = src_reg(value, scratch1, &mut code)?;
                            push_word(&mut code, encode_addi(10, r, 0)?);
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_TLV_LEN);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::JsonGetNumeric {
                            dest,
                            json,
                            key,
                            kind,
                        } => {
                            load_pointer(json, 10, scratch1, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                            load_pointer(key, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch2, 0)?);
                            push_syscall(
                                &mut code,
                                match kind {
                                    ir::WideNumericKind::Int => syscalls::SYSCALL_JSON_GET_INT,
                                    ir::WideNumericKind::Decimal => {
                                        syscalls::SYSCALL_JSON_GET_DECIMAL
                                    }
                                    ir::WideNumericKind::Quantity => {
                                        syscalls::SYSCALL_JSON_GET_QUANTITY
                                    }
                                },
                            );
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::JsonGetJson { dest, json, key }
                        | Instr::JsonGetName { dest, json, key }
                        | Instr::JsonGetAccountId { dest, json, key }
                        | Instr::JsonGetAssetDefinitionId { dest, json, key }
                        | Instr::JsonGetNftId { dest, json, key }
                        | Instr::JsonGetBlobHex { dest, json, key }
                        | Instr::JsonGetString { dest, json, key }
                        | Instr::JsonGetBool { dest, json, key } => {
                            // Typed JSON getters return one active-only Option handle in r10.
                            load_pointer(json, 10, scratch1, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            // Both args must be in INPUT for pointer-ABI validation.
                            push_word(&mut code, encode_addi(scratch2, 10, 0)?);
                            load_pointer(key, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch2, 0)?);
                            let syscall = match instr {
                                Instr::JsonGetJson { .. } => syscalls::SYSCALL_JSON_GET_JSON,
                                Instr::JsonGetName { .. } => syscalls::SYSCALL_JSON_GET_NAME,
                                Instr::JsonGetAccountId { .. } => {
                                    syscalls::SYSCALL_JSON_GET_ACCOUNT_ID
                                }
                                Instr::JsonGetAssetDefinitionId { .. } => {
                                    syscalls::SYSCALL_JSON_GET_ASSET_DEFINITION_ID
                                }
                                Instr::JsonGetNftId { .. } => syscalls::SYSCALL_JSON_GET_NFT_ID,
                                Instr::JsonGetBlobHex { .. } => syscalls::SYSCALL_JSON_GET_BLOB_HEX,
                                Instr::JsonGetString { .. } => syscalls::SYSCALL_JSON_GET_STRING,
                                Instr::JsonGetBool { .. } => syscalls::SYSCALL_JSON_GET_BOOL,
                                _ => unreachable!(),
                            };
                            // `push_syscall` keeps the 8-bit form for the original
                            // getters and uses the extended form above 0xFF.
                            push_syscall(&mut code, syscall);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::NameDecode { dest, blob } => {
                            // r10=&NoritoBytes; publish; SCALL NAME_DECODE; move
                            load_pointer(blob, 10, scratch1, DataKind::NoritoBytes, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_NAME_DECODE);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::SchemaEncode { dest, schema, json } => {
                            // r10=&Name; publish; r11=&Json; publish; SCALL
                            load_pointer(schema, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch1, 10, 0)?);
                            load_pointer(json, 10, scratch2, DataKind::Json, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch1, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_SCHEMA_ENCODE);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::SchemaDecode { dest, schema, blob } => {
                            // r10=&Name; publish; r11=&NoritoBytes or &Blob; publish; SCALL
                            load_pointer(schema, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(scratch1, 10, 0)?);
                            load_pointer(blob, 10, scratch2, DataKind::NoritoBytes, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_word(&mut code, encode_addi(11, 10, 0)?);
                            push_word(&mut code, encode_addi(10, scratch1, 0)?);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_SCHEMA_DECODE);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::SchemaInfo { dest, schema } => {
                            load_pointer(schema, 10, scratch1, DataKind::Name, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_SCHEMA_INFO);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::VrfVerify { dest, request } => {
                            load_pointer(request, 10, scratch1, DataKind::Blob, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_NORMALIZE_NORITO_BYTES);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_VRF_VERIFY);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::VrfVerifyBatch { dest, batch } => {
                            load_pointer(batch, 10, scratch1, DataKind::Blob, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall(&mut code, syscalls::SYSCALL_NORMALIZE_NORITO_BYTES);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_VRF_VERIFY_BATCH);
                            spill_syscall_result(dest, &mut code)?;
                        }
                        Instr::AxtBegin { descriptor } => {
                            load_pointer(
                                descriptor,
                                10,
                                scratch1,
                                DataKind::AxtDescriptor,
                                &mut code,
                            )?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_AXT_BEGIN);
                        }
                        Instr::AxtTouch { dsid, manifest } => {
                            load_pointer(dsid, 10, scratch1, DataKind::DataSpaceId, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            if let Some(m) = manifest {
                                if let Some(s) = string_map.get(&(func_idx, *m)) {
                                    if decode_axt_touch_manifest_literal(s).is_none() {
                                        let err = format!(
                                            "invalid AXT touch manifest literal `{s}`: expected one canonical, context-valid TouchManifest frame"
                                        );
                                        return Err(i18n::translate(
                                            self.lang,
                                            Message::SemanticError(&err),
                                        ));
                                    }
                                    let key = DataKey(DataKind::NoritoBytes, s.clone());
                                    emit_literal_load(&mut code, &fixups, 11, key);
                                } else {
                                    let r = src_reg(m, scratch2, &mut code)?;
                                    push_word(&mut code, encode_addi(11, r, 0)?);
                                }
                                code.extend_from_slice(&publish_tlv);
                            } else {
                                push_word(&mut code, encode_addi(11, 0, 0)?);
                            }
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_AXT_TOUCH);
                        }
                        Instr::StageAnchoredSpend { spend } => {
                            load_pointer(
                                spend,
                                10,
                                scratch1,
                                DataKind::AxtAnchoredSpendV1,
                                &mut code,
                            )?;
                            code.extend_from_slice(&publish_tlv);
                            push_syscall_imm8(
                                &mut code,
                                syscalls::SYSCALL_AXT_STAGE_ANCHORED_SPEND,
                            );
                        }
                        Instr::VerifyDsProof { dsid, proof } => {
                            load_pointer(dsid, 10, scratch1, DataKind::DataSpaceId, &mut code)?;
                            code.extend_from_slice(&publish_tlv);
                            if let Some(p) = proof {
                                load_pointer(p, 11, scratch2, DataKind::ProofBlob, &mut code)?;
                                code.extend_from_slice(&publish_tlv);
                            } else {
                                push_word(&mut code, encode_addi(11, 0, 0)?);
                            }
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_VERIFY_DS_PROOF);
                        }
                        Instr::AxtCommit => {
                            push_syscall_imm8(&mut code, syscalls::SYSCALL_AXT_COMMIT);
                        }
                    }
                    statement_sources.record(
                        &mut statement_seeds,
                        &func.name,
                        bb.label,
                        instruction_index,
                        instruction_start,
                        code.len(),
                    );
                }
                // end for instr in &bb.instrs
                let terminator_start = code.len();
                #[cfg(test)]
                emission_profile::finish(emission_observation, code.len());
                allocation_position.set(next_allocation_position);
                emit_split_reloads(next_allocation_position, &tuple_map, &mut code)?;
                next_allocation_position = next_allocation_position.saturating_add(1);
                match &bb.terminator {
                    terminator @ (Terminator::Return(_)
                    | Terminator::Return2(_, _)
                    | Terminator::ReturnN(_)) => {
                        let values = match terminator {
                            Terminator::Return(value) => value.iter().copied().collect::<Vec<_>>(),
                            Terminator::Return2(first, second) => vec![*first, *second],
                            Terminator::ReturnN(values) => values.clone(),
                            _ => unreachable!("return terminator selected above"),
                        };
                        let result_count = values.len().max(1);
                        if result_count != signature.result_word_count() {
                            return Err(format!(
                                "function `{}` has an inconsistent result table",
                                func.name
                            ));
                        }
                        emit_load64(
                            &mut code,
                            &fixups,
                            scratchd,
                            sp,
                            frame.result_base_slot as i64,
                            Some(scratch2),
                        )?;
                        if values.is_empty() {
                            emit_store64(&mut code, &fixups, scratchd, 0, 0, scratch2)?;
                        }
                        for (index, value) in values.iter().enumerate() {
                            let source = if let Some(kind) =
                                dataref_kind_map.get(&(func_idx, *value)).copied()
                                && let Some(literal) = string_map.get(&(func_idx, *value))
                            {
                                emit_literal_load(
                                    &mut code,
                                    &fixups,
                                    scratch1,
                                    literal_data_key(value, kind, literal),
                                );
                                scratch1
                            } else {
                                src_reg(value, scratch1, &mut code)?
                            };
                            emit_store64(
                                &mut code,
                                &fixups,
                                scratchd,
                                source,
                                (index * 8) as i64,
                                scratch2,
                            )?;
                        }
                        // Publish only after every slot has been written. Runtime return
                        // validation independently checks ownership, coverage, and role tags.
                        push_word(&mut code, encode_addi(10, scratchd, 0)?);
                        emit_i64_literal_load(&mut code, &fixups, 11, result_count as i64);
                        if let Some(label) = shared_epilogue {
                            let at = reserve_word(&mut code);
                            jump_fixups.push(JumpFixup {
                                at,
                                target_label: label,
                            });
                        } else {
                            frame_emission::emit_epilogue(
                                &mut code,
                                &fixups,
                                &saved_regs,
                                save_base,
                                saves_return_address,
                                local_frame,
                            )?;
                        }
                    }
                    Terminator::Jump(target) => {
                        if next_label != Some(*target) {
                            let at = reserve_word(&mut code);
                            jump_fixups.push(JumpFixup {
                                at,
                                target_label: target.0,
                            });
                        }
                    }
                    Terminator::Branch {
                        cond,
                        then_bb,
                        else_bb,
                    } => {
                        let (funct3, rs1, rs2) = if let Some((op, left, right)) = fused_relational {
                            let left = src_reg(&left, scratch1, &mut code)?;
                            let right = src_reg(&right, scratch2, &mut code)?;
                            signed_branch_plan(op, left, right)
                                .expect("relational branch has a signed branch plan")
                        } else {
                            (0x1, src_reg(cond, scratch1, &mut code)?, 0)
                        };
                        if next_label == Some(*then_bb) {
                            // True falls through by skipping the one-word false
                            // transfer. This is the common structured-CFG layout
                            // and keeps the complete conditional transfer to two
                            // words even when the false target needs JMP.
                            push_word(&mut code, encode_branch_rv(funct3, rs1, rs2, 8)?);
                            let transfer_at = reserve_word(&mut code);
                            branch_fixups.push(BranchFixup::One {
                                transfer_at,
                                target_label: else_bb.0,
                            });
                        } else if next_label == Some(*else_bb) {
                            // False falls through. Every supported branch opcode
                            // is paired with its logical inverse in the adjacent
                            // opcode (`BEQ/BNE`, `BLT/BGE`, `BLTU/BGEU`).
                            push_word(&mut code, encode_branch_rv(funct3 ^ 1, rs1, rs2, 8)?);
                            let transfer_at = reserve_word(&mut code);
                            branch_fixups.push(BranchFixup::One {
                                transfer_at,
                                target_label: then_bb.0,
                            });
                        } else {
                            return Err(format!(
                                "structured Kotodama CFG invariant failed in `{}`: conditional block {:?} has no adjacent successor after layout",
                                func.name, bb.label
                            ));
                        }
                    }
                }
                statement_sources.record(
                    &mut statement_seeds,
                    &func.name,
                    bb.label,
                    bb.instrs.len(),
                    terminator_start,
                    code.len(),
                );
            }
            debug_assert_eq!(
                next_allocation_position,
                func.blocks
                    .iter()
                    .map(|block| block.instrs.len().saturating_add(1))
                    .sum::<usize>(),
                "code generation and live-interval positions diverged"
            );
            if let Some(label) = shared_epilogue {
                block_offsets.insert(label, code.len() - func_base);
                frame_emission::emit_epilogue(
                    &mut code,
                    &fixups,
                    &saved_regs,
                    save_base,
                    saves_return_address,
                    local_frame,
                )?;
            }
            for fix in jump_fixups {
                let target_off = *block_offsets.get(&fix.target_label).ok_or_else(|| {
                    format!(
                        "missing block offset for label {} in {}",
                        fix.target_label, func.name
                    )
                })?;
                let target_pc = func_base + target_off;
                patch_or_defer_transfer(
                    &mut code,
                    fix.at,
                    target_pc,
                    TransferKind::Jump,
                    &mut deferred_transfers,
                )?;
            }
            for fix in branch_fixups {
                match fix {
                    BranchFixup::One {
                        transfer_at,
                        target_label,
                    } => {
                        let target = *block_offsets.get(&target_label).ok_or_else(|| {
                            format!(
                                "missing branch target offset for label {} in {}",
                                target_label, func.name
                            )
                        })?;
                        patch_or_defer_transfer(
                            &mut code,
                            transfer_at,
                            func_base + target,
                            TransferKind::Jump,
                            &mut deferred_transfers,
                        )?;
                    }
                }
            }
            if share_nominal_abort
                && nominal_abort_tail.is_none()
                && nominal_abort_sites.len() > initial_nominal_abort_sites
            {
                // Every source terminator above already returns or transfers.
                // Only a taken nominal-abort edge reaches this compiler-owned
                // tail; the canonical syscall marks the VM halted before return.
                nominal_abort_tail = Some(code.len());
                compact_emission::emit_nominal_abort_tail(&mut code)?;
            }
            let function_end = code.len() as u64;
            let debug_seed = &mut function_debug_seeds[debug_seed_index];
            debug_seed.pc_end = function_end;
            uses_zk_global |= uses_zk;
        }
        if let Some(target) = nominal_abort_tail {
            for at in nominal_abort_sites {
                patch_or_defer_transfer(
                    &mut code,
                    at,
                    target,
                    TransferKind::Jump,
                    &mut deferred_transfers,
                )?;
            }
        }
        // Patch call sites now that function offsets are known.
        for (at, callee, _caller) in &call_fixups {
            let target = *func_start_offsets.get(callee).ok_or_else(|| {
                i18n::translate(self.lang, Message::SemanticError("unknown callee"))
            })?;
            patch_or_defer_transfer(
                &mut code,
                *at,
                target,
                TransferKind::Call,
                &mut deferred_transfers,
            )?;
        }
        let (relaxed_code, code_offsets) = relax_control_transfers_with_trampolines(
            code,
            &deferred_transfers,
            TRAMPOLINE_HOP_BYTES,
        )?;
        code = relaxed_code;
        let mut fixups = fixups.into_inner();
        for (at, _, _) in &mut fixups {
            *at = code_offsets.instruction(*at);
        }
        for offset in func_start_offsets.values_mut() {
            *offset = code_offsets.entry(*offset);
        }
        for callable in &mut callables {
            callable.entry_pc = code_offsets.entry(callable.entry_pc as usize) as u64;
        }
        callables.sort_by_key(|callable| callable.entry_pc);
        for seed in &mut function_debug_seeds {
            let old_start = usize::try_from(seed.pc_start)
                .map_err(|_| "function start does not fit usize".to_owned())?;
            let old_end = usize::try_from(seed.pc_end)
                .map_err(|_| "function end does not fit usize".to_owned())?;
            seed.pc_start = u64::try_from(code_offsets.entry(old_start))
                .map_err(|_| "relaxed function start does not fit u64".to_owned())?;
            seed.pc_end = u64::try_from(code_offsets.entry(old_end))
                .map_err(|_| "relaxed function end does not fit u64".to_owned())?;
        }
        for seed in &mut statement_seeds {
            seed.start = code_offsets.entry(seed.start);
            seed.end = code_offsets.entry(seed.end);
        }
        uses_vector_global |= detect_vector_usage(&code);
        uses_zk_global |= detect_zk_usage(&code);
        // Build metadata and finalize program (with data appended).
        // Resolve mode bits from emitted operations and compiler-owned build policy.
        let mut mode = 0u8;
        if uses_zk_global || self.opts.force_zk {
            mode |= metadata::mode::ZK;
        }
        if uses_vector_global {
            mode |= metadata::mode::VECTOR;
        }
        let meta = ProgramMetadata {
            version_major: 1,
            // Every profile uses the sole current header. Test harnesses omit
            // CNTR and require the explicit compiler-owned test capability;
            // production artifacts embed their admitted contract interface.
            version_minor: 1,
            mode,
            vector_length: 0,
            max_cycles: self.opts.max_cycles,
            abi_version: KOTODAMA_ABI_VERSION,
        };
        // Build the packed typed-data section and its stable indexed table.
        use iroha_crypto::Hash as IrohaHash;
        use iroha_data_model::prelude::*;
        use iroha_primitives::json::Json;
        // Stable key order based on first occurrence in fixups. Also include datarefs seen even if unused
        // in emitted code to ensure TLVs are generated (useful for constructor-only samples/tests).
        let mut key_order: IndexSet<DataKey> = IndexSet::new();
        for (_, _, k) in &fixups {
            key_order.insert(k.clone());
        }
        // Extend with datarefs not already present
        for (k, v) in &datarefs {
            let dk = match k {
                DRK::Account => DataKey(DataKind::Account, v.clone()),
                DRK::AssetDef => DataKey(DataKind::AssetDef, v.clone()),
                DRK::Name => DataKey(DataKind::Name, v.clone()),
                DRK::Json => DataKey(DataKind::Json, v.clone()),
                DRK::NftId => DataKey(DataKind::NftId, v.clone()),
                DRK::AssetId => DataKey(DataKind::AssetId, v.clone()),
                DRK::Domain => DataKey(DataKind::Domain, v.clone()),
                DRK::Blob => DataKey(DataKind::Blob, v.clone()),
                DRK::NoritoBytes => DataKey(DataKind::NoritoBytes, v.clone()),
                DRK::DataSpaceId => DataKey(DataKind::DataSpaceId, v.clone()),
                DRK::AxtDescriptor => DataKey(DataKind::AxtDescriptor, v.clone()),
                DRK::AxtAnchoredSpendV1 => DataKey(DataKind::AxtAnchoredSpendV1, v.clone()),
                DRK::ProofBlob => DataKey(DataKind::ProofBlob, v.clone()),
                DRK::SoracloudRequest => DataKey(DataKind::SoracloudRequest, v.clone()),
                DRK::SoracloudResponse => DataKey(DataKind::SoracloudResponse, v.clone()),
                DRK::Int => DataKey(DataKind::Int, v.clone()),
                DRK::Decimal => DataKey(DataKind::Decimal, v.clone()),
                DRK::Quantity => DataKey(DataKind::Quantity, v.clone()),
            };
            key_order.insert(dk);
        }
        validate_literal_count(key_order.len())?;
        let mut get_or_insert_data = |key: &DataKey| -> Result<u64, String> {
            if let Some(off) = data_offsets.get(key) {
                return Ok(*off);
            }
            if let DataKey(DataKind::I64, raw) = key {
                let value = raw.parse::<i64>().map_err(|error| {
                    format!("invalid compiler-owned int literal `{raw}`: {error}")
                })?;
                let off = data_bytes.len() as u64;
                data_bytes.extend_from_slice(&value.to_le_bytes());
                data_offsets.insert(key.clone(), off);
                return Ok(off);
            }
            let numeric_kind = match key.0 {
                DataKind::Int => Some(DRK::Int),
                DataKind::Decimal => Some(DRK::Decimal),
                DataKind::Quantity => Some(DRK::Quantity),
                _ => None,
            };
            if let Some(kind) = numeric_kind {
                let bytes = encode_pointer_tlv_bytes(kind, &key.1, false).ok_or_else(|| {
                    let error = format!(
                        "invalid {} literal `{}`",
                        match kind {
                            DRK::Int => "int",
                            DRK::Decimal => "decimal",
                            DRK::Quantity => "quantity",
                            _ => unreachable!("numeric kind selected above"),
                        },
                        key.1
                    );
                    i18n::translate(self.lang, Message::SemanticError(&error))
                })?;
                let off = data_bytes.len() as u64;
                data_bytes.extend_from_slice(&bytes);
                data_offsets.insert(key.clone(), off);
                return Ok(off);
            }
            let (type_id, mut payload) = match key {
                DataKey(DataKind::I64, _) => unreachable!("int literals return above"),
                DataKey(DataKind::Int | DataKind::Decimal | DataKind::Quantity, _) => {
                    unreachable!("numeric literals return above")
                }
                DataKey(DataKind::Account, s) => {
                    let id = AccountId::parse_encoded(s).map_err(|e| {
                        let err = format!("invalid AccountId literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        1u16,
                        ivm_abi::codec::encode_canonical_norito(&id)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid AccountId literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::AssetDef, s) => {
                    let id = AssetDefinitionId::parse_address_literal(s).map_err(|e| {
                        let err = format!("invalid AssetDefinitionId literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        2u16,
                        ivm_abi::codec::encode_canonical_norito(&id)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid AssetDefinitionId literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::NftId, s) => {
                    let id: iroha_data_model::nft::NftId = s.parse().map_err(|e| {
                        let err = format!("invalid NftId literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        5u16,
                        ivm_abi::codec::encode_canonical_norito(&id)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid NftId literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::AssetId, s) => {
                    let id: iroha_data_model::asset::AssetId = s.parse().map_err(|e| {
                        let err = format!("invalid AssetId literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        7u16,
                        ivm_abi::codec::encode_canonical_norito(&id)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid AssetId literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::Name, s) => {
                    let nm: Name = s.parse().map_err(|e| {
                        let err = format!("invalid Name literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        3u16,
                        ivm_abi::codec::encode_canonical_norito(&nm)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid Name literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::Json, s) => {
                    // JSON literals must be valid JSON text. (Use `norito_bytes` for opaque bytes.)
                    let value = norito::json::parse_value(s).map_err(|e| {
                        let err = format!("invalid JSON literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    let json = Json::from_norito_value_ref(&value).map_err(|e| {
                        let err = format!("invalid JSON literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        4u16,
                        ivm_abi::codec::encode_canonical_norito(&json)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid JSON literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::Domain, s) => {
                    let id = iroha_model_base::domain::DomainId::parse_fully_qualified(s).map_err(
                        |e| {
                            let err = format!("invalid DomainId literal `{s}`: {e}");
                            i18n::translate(self.lang, Message::SemanticError(&err))
                        },
                    )?;
                    (
                        8u16,
                        ivm_abi::codec::encode_canonical_norito(&id)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid DomainId literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::String, s) => (6u16, s.as_bytes().to_vec()),
                DataKey(DataKind::Blob, s) => (
                    6u16,
                    decode_hex_or_raw_bytes(s).map_err(|e| {
                        let err = format!("invalid Blob literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?,
                ),
                DataKey(DataKind::NoritoBytes, s) => {
                    let bytes = decode_hex_or_raw_bytes(s).map_err(|e| {
                        let err = format!("invalid NoritoBytes literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (9u16, bytes)
                }
                DataKey(DataKind::DataSpaceId, s) => {
                    if let Some(raw) = parse_u64_literal(s) {
                        let id = iroha_model_base::topology::DataSpaceId::new(raw);
                        (
                            PointerType::DataSpaceId as u16,
                            ivm_abi::codec::encode_canonical_norito(&id)
                                .map_err(|e| e.to_string())
                                .map_err(|e| {
                                    let err = format!("invalid DataSpaceId literal `{s}`: {e}");
                                    i18n::translate(self.lang, Message::SemanticError(&err))
                                })?,
                        )
                    } else {
                        let bytes = decode_hex_or_raw_bytes(s).map_err(|e| {
                            let err = format!("invalid DataSpaceId literal `{s}`: {e}");
                            i18n::translate(self.lang, Message::SemanticError(&err))
                        })?;
                        let value: iroha_model_base::topology::DataSpaceId =
                            ivm_abi::codec::decode_canonical_norito(&bytes).map_err(|e| {
                                let err = format!(
                                    "invalid DataSpaceId literal `{s}`: cannot decode ({e})"
                                );
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?;
                        (
                            PointerType::DataSpaceId as u16,
                            ivm_abi::codec::encode_canonical_norito(&value)
                                .map_err(|e| e.to_string())
                                .map_err(|e| {
                                    let err = format!("invalid DataSpaceId literal `{s}`: {e}");
                                    i18n::translate(self.lang, Message::SemanticError(&err))
                                })?,
                        )
                    }
                }
                DataKey(DataKind::AxtDescriptor, s) => {
                    let bytes = decode_hex_or_raw_bytes(s).map_err(|e| {
                        let err = format!("invalid AxtDescriptor literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    let value: crate::axt::AxtDescriptor =
                        ivm_abi::codec::decode_canonical_norito(&bytes).map_err(|e| {
                            let err =
                                format!("invalid AxtDescriptor literal `{s}`: cannot decode ({e})");
                            i18n::translate(self.lang, Message::SemanticError(&err))
                        })?;
                    crate::axt::validate_descriptor(&value).map_err(|e| {
                        let err = format!(
                            "invalid AxtDescriptor literal `{s}`: invalid descriptor ({e})"
                        );
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        PointerType::AxtDescriptor as u16,
                        ivm_abi::codec::encode_canonical_norito(&value)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid AxtDescriptor literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::AxtAnchoredSpendV1, s) => {
                    let bytes = decode_hex_or_raw_bytes(s).map_err(|e| {
                        let err = format!("invalid AxtAnchoredSpendV1 literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    let value: iroha_data_model::nexus::AxtAnchoredSpendV1 =
                        ivm_abi::codec::decode_canonical_norito(&bytes).map_err(|e| {
                            let err = format!(
                                "invalid AxtAnchoredSpendV1 literal `{s}`: cannot decode ({e})"
                            );
                            i18n::translate(self.lang, Message::SemanticError(&err))
                        })?;
                    value.issuer_payload_v1().map_err(|e| {
                        let err = format!(
                            "invalid AxtAnchoredSpendV1 literal `{s}`: inconsistent signed binding ({e})"
                        );
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        PointerType::AxtAnchoredSpendV1 as u16,
                        ivm_abi::codec::encode_canonical_norito(&value)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid AxtAnchoredSpendV1 literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::ProofBlob, s) => {
                    let bytes = decode_hex_or_raw_bytes(s).map_err(|e| {
                        let err = format!("invalid ProofBlob literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    let value: crate::axt::ProofBlob =
                        ivm_abi::codec::decode_canonical_norito(&bytes).map_err(|e| {
                            let err =
                                format!("invalid ProofBlob literal `{s}`: cannot decode ({e})");
                            i18n::translate(self.lang, Message::SemanticError(&err))
                        })?;
                    crate::axt::validate_proof_blob(&value).map_err(|e| {
                        let err = format!("invalid ProofBlob literal `{s}`: invalid proof ({e})");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        PointerType::ProofBlob as u16,
                        ivm_abi::codec::encode_canonical_norito(&value)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid ProofBlob literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::SoracloudRequest, s) => {
                    let bytes = decode_hex_or_raw_bytes(s).map_err(|e| {
                        let err = format!("invalid SoracloudRequest literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    let value: iroha_data_model::soracloud::SoracloudHostRequestEnvelopeV1 =
                        ivm_abi::codec::decode_canonical_norito(&bytes).map_err(|e| {
                            let err = format!(
                                "invalid SoracloudRequest literal `{s}`: cannot decode ({e})"
                            );
                            i18n::translate(self.lang, Message::SemanticError(&err))
                        })?;
                    value.validate().map_err(|e| {
                        let err = format!("invalid SoracloudRequest literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        PointerType::SoracloudRequest as u16,
                        ivm_abi::codec::encode_canonical_norito(&value)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid SoracloudRequest literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
                DataKey(DataKind::SoracloudResponse, s) => {
                    let bytes = decode_hex_or_raw_bytes(s).map_err(|e| {
                        let err = format!("invalid SoracloudResponse literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    let value: iroha_data_model::soracloud::SoracloudHostResponseEnvelopeV1 =
                        ivm_abi::codec::decode_canonical_norito(&bytes).map_err(|e| {
                            let err = format!(
                                "invalid SoracloudResponse literal `{s}`: cannot decode ({e})"
                            );
                            i18n::translate(self.lang, Message::SemanticError(&err))
                        })?;
                    value.validate().map_err(|e| {
                        let err = format!("invalid SoracloudResponse literal `{s}`: {e}");
                        i18n::translate(self.lang, Message::SemanticError(&err))
                    })?;
                    (
                        PointerType::SoracloudResponse as u16,
                        ivm_abi::codec::encode_canonical_norito(&value)
                            .map_err(|e| e.to_string())
                            .map_err(|e| {
                                let err = format!("invalid SoracloudResponse literal `{s}`: {e}");
                                i18n::translate(self.lang, Message::SemanticError(&err))
                            })?,
                    )
                }
            };
            // TLV envelope: type_id (be), version=1, len (be u32), payload, hash (32 bytes blake2b-32)
            let mut v = Vec::with_capacity(2 + 1 + 4 + payload.len() + 32);
            v.extend_from_slice(&type_id.to_be_bytes());
            v.push(1u8);
            v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            v.append(&mut payload);
            let h = IrohaHash::new(&v[2 + 1 + 4..]);
            v.extend_from_slice(h.as_ref());
            let bytes = v;
            let off = data_bytes.len() as u64;
            data_bytes.extend_from_slice(&bytes);
            data_offsets.insert(key.clone(), off);
            Ok(off)
        };
        let entrypoint_start_offsets = func_start_offsets.clone();
        let entrypoint_descriptors = build_entrypoint_descriptors(
            &typed,
            &access_sets,
            &ir_prog.functions,
            &hint_reports,
            &entrypoint_start_offsets,
        )?;
        if self.opts.mode == CompilerMode::Production
            && let Some(entrypoint) = entrypoint_descriptors.iter().find(|entrypoint| {
                entrypoint.access_hints_complete == Some(false)
                    && !production_allows_incomplete_access_hints(&entrypoint.access_hints_skipped)
            })
        {
            let reasons = if entrypoint.access_hints_skipped.is_empty() {
                "no reason recorded".to_owned()
            } else {
                entrypoint.access_hints_skipped.join("; ")
            };
            return Err(format!(
                "E_ACCESS_INCOMPLETE: entrypoint `{}` has incomplete compiler-derived access metadata: {reasons}",
                entrypoint.name
            ));
        }
        let access_set_hints = build_access_set_hints(
            &ir_prog.functions,
            &access_sets,
            &state_descriptors,
            include_hints,
        )?;
        let message_entries = build_message_entries(&typed.message_entries);
        let mut feature_bits = 0u64;
        if meta.mode & metadata::mode::ZK != 0 {
            feature_bits |= CONTRACT_FEATURE_BIT_ZK;
        }
        if meta.mode & metadata::mode::VECTOR != 0 {
            feature_bits |= CONTRACT_FEATURE_BIT_VECTOR;
        }
        let contract_interface = EmbeddedContractInterfaceV1 {
            callables,
            seiyaku_name: typed.unit.name.clone(),
            compiler_fingerprint: COMPILER_FINGERPRINT.to_owned(),
            abi_hash: crate::syscalls::compute_abi_hash(crate::SyscallPolicy::AbiV1),
            features_bitmap: feature_bits,
            access_set_hints: access_set_hints.clone(),
            permissions: typed.permissions.clone(),
            events: typed.events.clone(),
            kotoba: message_entries.clone(),
            entrypoints: entrypoint_descriptors.clone(),
            error_types: typed.error_types.clone(),
            enum_types: typed.enum_types.clone(),
            error_messages: typed.error_messages.clone(),
            states: state_descriptors,
        };
        // Compute the indexed literal table and patch LDLIT/LDI64 words.
        // Production contracts use `[header | CNTR | LTLB? | code]`; local
        // test harnesses use the generic `[header | LTLB? | code]` profile.
        let meta_bytes = meta.encode();
        let contract_section = match self.opts.mode {
            CompilerMode::Production => contract_interface.encode_section(),
            CompilerMode::Test => Vec::new(),
        };
        let need_literals = !key_order.is_empty();
        // Literal table length and offsets
        let lit_count = key_order.len() as u64;
        let lit_size = lit_count * 8;
        let lit_header_size: u64 = if need_literals { 16 } else { 0 };
        let data_base_rel = lit_header_size + lit_size;
        let mut lit_bytes: Vec<u8> = Vec::with_capacity(lit_size as usize);
        for k in key_order.iter() {
            let data_off = get_or_insert_data(k)?;
            let relative_offset = data_base_rel
                .checked_add(data_off)
                .ok_or_else(|| "literal table offset overflow".to_owned())?;
            let descriptor = encode_literal_descriptor(k.0.literal_kind(), relative_offset)
                .ok_or_else(|| {
                    format!(
                        "literal table offset {relative_offset} exceeds the ABI-v1 56-bit domain"
                    )
                })?;
            lit_bytes.extend_from_slice(&descriptor.to_le_bytes());
        }
        // Sora Nexus contracts still have legitimate dynamic ledger operations
        // whose exact account/asset keys are only known from the call payload.
        // Keep emitting compiler-owned fallback hints for those paths and let
        // the scheduler's dynamic prepass/conservative fallback serialize them.
        // Patch each one-word load with the stable table index assigned above.
        for (at, rd, key) in &fixups {
            let index = key_order
                .get_index_of(key)
                .expect("literal fixup key must have a stable table index");
            patch_indexed_literal_load(
                &mut code,
                *at,
                *rd,
                u16::try_from(index).expect("literal count validated against u16 index range"),
                key.0.literal_kind(),
            );
        }
        // Final layout assembly
        let mut out = meta_bytes;
        out.extend_from_slice(&contract_section);
        let mut post_pad: usize = 0;
        if need_literals {
            let total_prefix = contract_section.len()
                + lit_header_size as usize
                + lit_size as usize
                + data_bytes.len();
            let rem = total_prefix % 4;
            if rem != 0 {
                post_pad = 4 - rem;
            }
        }
        if need_literals {
            let data_len = data_bytes.len() as u32;
            out.extend_from_slice(&LITERAL_SECTION_MAGIC);
            out.extend_from_slice(&(lit_count as u32).to_le_bytes());
            out.extend_from_slice(&(post_pad as u32).to_le_bytes());
            out.extend_from_slice(&data_len.to_le_bytes());
            out.extend_from_slice(&lit_bytes);
            out.extend_from_slice(&data_bytes);
            if post_pad != 0 {
                out.resize(out.len() + post_pad, 0u8);
            }
        }
        let code_start = out.len();
        out.extend_from_slice(&code);
        // Optional debug: dump compiled image as hex for tests/debugging when requested.
        if cfg!(any(test, debug_assertions)) && std::env::var_os("IVM_COMPILER_DEBUG").is_some() {
            let mut pairs: Vec<_> = func_start_offsets.iter().collect();
            pairs.sort_by_key(|(_, off)| **off);
            for (name, off) in pairs {
                eprintln!(
                    "[kotodama-compile] func {} @ 0x{:x} (code+0x{:x})",
                    name,
                    code_start + *off,
                    off
                );
            }
            // Print first 64 bytes of header+lit, then first 64 bytes of code if available.
            use std::fmt::Write as _;
            let mut hex = String::new();
            // Header bytes (first 64)
            for b in out.iter().take(64) {
                let _ = write!(&mut hex, "{b:02x}");
            }
            let _ = write!(&mut hex, " | ");
            // Code bytes (first 64) start after the CNTR/literal prefix.
            for b in out.iter().skip(code_start).take(64) {
                let _ = write!(&mut hex, "{b:02x}");
            }
            eprintln!("[kotodama-compile] header+lit(first64) | code(first64): {hex}");
        }
        let compile_report = build_compile_report(
            metadata::contract_code_hash(&out),
            &function_debug_seeds,
            &statement_seeds,
            code.len(),
            source_name.as_deref(),
            &typed.source_files,
            hint_diagnostics.clone(),
        );
        Ok(CompilationArtifacts {
            bytes: out,
            compile_report,
            contract_interface,
        })
    }
    /// Compile source and produce a manifest with code_hash and abi_hash.
    ///
    /// The returned `ContractManifest` includes
    /// - `code_hash`: domain-separated canonical hash of the complete deployable artifact
    /// - `abi_hash`: hash of the allowed syscall surface for the program's `abi_version`
    pub fn compile_source_with_manifest(
        &self,
        src: &str,
    ) -> Result<
        (
            Vec<u8>,
            iroha_data_model::smart_contract::manifest::ContractManifest,
        ),
        String,
    > {
        let (bytes, manifest, _report) = self.compile_source_with_manifest_and_report(src)?;
        Ok((bytes, manifest))
    }
    /// Compile already linked typed HIR with native phase-aware diagnostics.
    pub(crate) fn compile_typed_program_with_manifest_and_report_diagnostics(
        &self,
        program: TypedProgram,
        source_name: Option<&str>,
    ) -> Result<crate::session::CompileOutput, DiagnosticBundle> {
        let lowered = self.lower_typed_program(program, source_name)?;
        let ssa = self.construct_ssa_program(lowered)?;
        let optimized = self.optimize_ssa_program(ssa)?;
        let codegen = self.destroy_ssa_program(optimized)?;
        // Typed-identifier literals are rejected during semantic analysis, so
        // codegen failures carry no fabricated source position.
        // TODO: move the source-level checks that still run in `compile_codegen`
        // (literal-only arguments such as `build_submit_ballot_inline` and
        // pointer constructors, `E_ACCESS_INCOMPLETE`) into semantic analysis;
        // K3099 can then be worded as a compiler defect only.
        let artifacts = self.compile_codegen(codegen).map_err(|message| {
            let unit = source_name.map_or_else(String::new, |name| format!(" for `{name}`"));
            DiagnosticBundle::single(Diagnostic::error(
                "K3099",
                DiagnosticPhase::Lowering,
                format!("bytecode generation failed{unit}: {message}"),
                None,
            ))
        })?;
        self.manifest_from_artifacts(artifacts).map_err(|message| {
            native_diagnostic_bundle(
                "K4002",
                DiagnosticPhase::Artifact,
                source_name,
                None,
                message,
            )
        })
    }
    /// Compile source and produce a manifest plus compiler report data.
    pub fn compile_source_with_manifest_and_report(
        &self,
        src: &str,
    ) -> Result<
        (
            Vec<u8>,
            iroha_data_model::smart_contract::manifest::ContractManifest,
            CompileReport,
        ),
        String,
    > {
        let output = self.compile_source_output(src, None)?;
        Ok((output.artifact, output.manifest, output.report))
    }
    fn manifest_from_artifacts(
        &self,
        artifacts: CompilationArtifacts,
    ) -> Result<crate::session::CompileOutput, String> {
        let CompilationArtifacts {
            bytes,
            compile_report,
            contract_interface: generated_contract_interface,
        } = artifacts;
        let parsed = crate::metadata::ProgramMetadata::parse(&bytes)
            .map_err(|e| format!("manifest parse header: {e}"))?;
        let contract_interface = match (self.opts.mode, parsed.contract_interface) {
            (CompilerMode::Production, Some(embedded)) => {
                if embedded != generated_contract_interface {
                    return Err(
                        "manifest parse header: embedded contract interface differs from the compiler-owned descriptor"
                            .to_owned(),
                    );
                }
                embedded
            }
            (CompilerMode::Production, None) => {
                return Err("manifest parse header: missing embedded contract interface".to_owned());
            }
            (CompilerMode::Test, None) => generated_contract_interface,
            (CompilerMode::Test, Some(_)) => {
                return Err(
                    "manifest parse header: local test harness unexpectedly embeds a CNTR section"
                        .to_owned(),
                );
            }
        };
        let code_hash = crate::metadata::contract_code_hash(&bytes);
        if compile_report.artifact_hash != code_hash {
            return Err("compiler report hash does not match compiled artifact".to_owned());
        }
        let meta = parsed.metadata;
        // First release: emit manifests only for ABI v1
        let policy = match meta.abi_version {
            1 => crate::SyscallPolicy::AbiV1,
            v => return Err(format!("unsupported abi_version {v}; expected 1")),
        };
        let abi_hash_bytes = crate::syscalls::compute_abi_hash(policy);
        if contract_interface.abi_hash != abi_hash_bytes {
            return Err(
                "manifest assembly: compiler-owned interface abi_hash does not match the compiler ABI"
                    .to_owned(),
            );
        }
        let manifest = iroha_data_model::smart_contract::manifest::ContractManifest {
            seiyaku_name: Some(contract_interface.seiyaku_name.clone()),
            code_hash: Some(code_hash),
            abi_hash: Some(iroha_crypto::Hash::prehashed(contract_interface.abi_hash)),
            compiler_fingerprint: Some(contract_interface.compiler_fingerprint.clone()),
            features_bitmap: Some(contract_interface.features_bitmap),
            access_set_hints: contract_interface.access_set_hints.clone(),
            permissions: contract_interface.permissions.clone(),
            events: contract_interface.events.clone(),
            entrypoints: Some(
                contract_interface
                    .entrypoints
                    .iter()
                    .map(|entrypoint| entrypoint.to_manifest_descriptor())
                    .collect(),
            ),
            states: Some(manifest_state_descriptors(&contract_interface.states)),
            error_types: (!contract_interface.error_types.is_empty())
                .then_some(contract_interface.error_types.clone()),
            enum_types: contract_interface.enum_types.clone(),
            error_messages: (!contract_interface.error_messages.is_empty())
                .then_some(contract_interface.error_messages.clone()),
            kotoba: (!contract_interface.kotoba.is_empty())
                .then_some(contract_interface.kotoba.clone()),
            provenance: None,
        };
        Ok(crate::session::CompileOutput {
            artifact: bytes,
            contract_interface,
            manifest,
            report: compile_report,
        })
    }
    /// Compile source and produce a manifest plus access-hint diagnostics.
    pub fn compile_source_with_manifest_and_diagnostics(
        &self,
        src: &str,
    ) -> Result<
        (
            Vec<u8>,
            iroha_data_model::smart_contract::manifest::ContractManifest,
            AccessHintDiagnostics,
        ),
        String,
    > {
        let (bytes, manifest, report) = self.compile_source_with_manifest_and_report(src)?;
        Ok((bytes, manifest, report.access_hint_diagnostics))
    }
}
fn build_compile_report(
    artifact_hash: iroha_crypto::Hash,
    function_debug_seeds: &[FunctionDebugSeed],
    statement_seeds: &[statement_sources::Seed],
    code_len: usize,
    source_path: Option<&str>,
    source_files: &BTreeMap<crate::source::SourceId, crate::source::SourceFile>,
    access_hint_diagnostics: AccessHintDiagnostics,
) -> CompileReport {
    let mut entries = function_debug_seeds.to_vec();
    entries.sort_by_key(|seed| seed.pc_start);
    let mut source_map = Vec::new();
    let mut budget_report = Vec::with_capacity(entries.len());
    for seed in &entries {
        let pc_end = seed.pc_end.min(code_len as u64);
        let function_range = seed.source;
        let source =
            embedded_source_location(function_range, source_path, seed.location, source_files);
        let bytecode_bytes = pc_end.saturating_sub(seed.pc_start) as u32;
        let bytecode_words = bytecode_bytes / 4;
        source_map.push(EmbeddedSourceMapEntryV1 {
            function_name: seed.name.clone(),
            pc_start: seed.pc_start,
            pc_end,
            source: source.clone(),
        });
        budget_report.push(EmbeddedFunctionBudgetReportV1 {
            function_name: seed.name.clone(),
            pc_start: seed.pc_start,
            pc_end,
            bytecode_bytes,
            bytecode_words,
            frame_bytes: seed.frame_bytes,
            jump_span_words: bytecode_words,
            jump_range_risk: bytecode_words > i16::MAX as u32,
            source: Some(source),
        });
    }
    let statement_map = statement_seeds
        .iter()
        .map(|seed| EmbeddedSourceMapEntryV1 {
            function_name: seed.function_name.clone(),
            pc_start: seed.start as u64,
            pc_end: seed.end.min(code_len) as u64,
            source: embedded_source_location(
                Some(seed.source),
                source_path,
                SourceLocation { line: 1, column: 1 },
                source_files,
            ),
        })
        .collect();
    CompileReport {
        artifact_hash,
        source_map,
        statement_map,
        budget_report,
        access_hint_diagnostics,
    }
}
fn embedded_source_location(
    source: Option<crate::source::SourceRange>,
    fallback_path: Option<&str>,
    fallback_location: SourceLocation,
    source_files: &BTreeMap<crate::source::SourceId, crate::source::SourceFile>,
) -> EmbeddedSourceLocation {
    let file = source.and_then(|range| source_files.get(&range.source));
    let location = source
        .zip(file)
        .map(|(range, file)| file.line_column(range.range.start));
    EmbeddedSourceLocation {
        source_path: file
            .map(|file| file.name().to_owned())
            .or_else(|| fallback_path.map(ToOwned::to_owned)),
        source_id: source.map_or(0, |range| range.source.0),
        byte_start: source.map_or(0, |range| range.range.start),
        byte_end: source.map_or(0, |range| range.range.end),
        line: location.map_or_else(
            || u32::try_from(fallback_location.line).unwrap_or(u32::MAX),
            |location| u32::try_from(location.line).unwrap_or(u32::MAX),
        ),
        column: location.map_or_else(
            || u32::try_from(fallback_location.column).unwrap_or(u32::MAX),
            |location| u32::try_from(location.column).unwrap_or(u32::MAX),
        ),
    }
}
fn render_state_value_hint(hint: Option<&StatePathHint>) -> Option<String> {
    match hint? {
        StatePathHint::Path(path) => Some(format!("state:{path}")),
        // A known StateMap base does not prove the canonical runtime key.
        // Dynamic children must retain the scheduler's state-wide fallback.
        StatePathHint::NameBase(_) | StatePathHint::DynamicMapChild => None,
    }
}
fn render_state_scan_hint(hint: Option<&StatePathHint>) -> Option<String> {
    match hint? {
        StatePathHint::Path(path) if !path.contains('/') => Some(format!("state:{path}[*]")),
        // Nested or computed prefixes are not represented precisely by the
        // first-release scheduler wildcard grammar.
        StatePathHint::Path(_) | StatePathHint::NameBase(_) | StatePathHint::DynamicMapChild => {
            None
        }
    }
}
fn insert_state_hint(keys: &mut IndexSet<String>, key: String) {
    keys.insert(key);
}
/// Preserve exact key access hints only when every canonical record atom is known.
fn literal_state_value_record(
    function: usize,
    schema: ir::Temp,
    words: &[ir::Temp],
    literals: &HashMap<(usize, ir::Temp), String>,
    kinds: &HashMap<(usize, ir::Temp), ir::DataRefKind>,
    integers: &HashMap<(usize, ir::Temp), i64>,
    strings: &HashSet<(usize, ir::Temp)>,
) -> Option<String> {
    use ivm_abi::state_value::{
        StateValueAtomV1 as Atom, StateValueKindV1 as Kind, StateValueNodeV1 as Node,
        StateValueRecordV1, StateValueSchemaV1, state_value_schema_hash_v1,
    };
    let schema_bytes = decode_norito_literal_payload(literals.get(&(function, schema))?)?;
    let schema: StateValueSchemaV1 = ivm_abi::codec::decode_canonical_norito(&schema_bytes).ok()?;
    if !schema.validate() {
        return None;
    }
    let mut atoms = Vec::with_capacity(words.len());
    let mut index = 0;
    for node in &schema.nodes {
        let Node::Leaf(kind) = node else {
            if matches!(node, Node::Tuple { .. }) {
                continue;
            }
            return None;
        };
        let word = *words.get(index)?;
        index += 1;
        let key = (function, word);
        atoms.push(if *kind == Kind::Bool {
            Atom::Bool(match integers.get(&key)? {
                0 => false,
                1 => true,
                _ => return None,
            })
        } else {
            let data_kind = *kinds.get(&key)?;
            if pointer_type_for_kind(data_kind) != kind.pointer_type() {
                return None;
            }
            Atom::Pointer(encode_pointer_tlv_bytes(
                data_kind,
                literals.get(&key)?,
                strings.contains(&key),
            )?)
        });
    }
    if index != words.len() || !schema.validate_atoms(&atoms) {
        return None;
    }
    let record = StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&schema_bytes),
        atoms,
    };
    let encoded = ivm_abi::codec::encode_canonical_norito(&record).ok()?;
    (encoded.len() <= syscalls::STATE_MAP_MAX_KEY_BYTES)
        .then(|| format!("0x{}", hex::encode(encoded)))
}
fn state_path_for_norito_key(base: &str, raw: &str) -> Option<String> {
    let bytes = decode_hex_or_raw_bytes(raw).ok()?;
    if bytes.is_empty() || bytes.len() > syscalls::STATE_MAP_MAX_KEY_BYTES {
        return None;
    }
    let mut out = String::with_capacity(base.len() + 1 + bytes.len().saturating_mul(2));
    out.push_str(base);
    out.push('/');
    out.push_str(&hex::encode(bytes));
    StatePath::try_from(out).ok().map(|path| path.to_string())
}
fn state_path_from_norito_literal(raw: &str) -> Option<String> {
    let bytes = decode_hex_or_raw_bytes(raw).ok()?;
    ivm_abi::codec::decode_canonical_norito::<StatePath>(&bytes)
        .ok()
        .map(|path| path.to_string())
}
fn build_access_set_hints(
    ir_functions: &[ir::Function],
    access_sets: &[AccessSets],
    state_descriptors: &[EmbeddedStateDescriptor],
    include_hints: bool,
) -> Result<Option<AccessSetHints>, String> {
    if !include_hints {
        return Ok(None);
    }
    let mut reads: BTreeSet<String> = BTreeSet::new();
    let mut writes: BTreeSet<String> = BTreeSet::new();
    for set in access_sets {
        reads.extend(set.reads.iter().cloned());
        writes.extend(set.writes.iter().cloned());
    }
    let (dynamic_reads, dynamic_writes) =
        collect_dynamic_access_hints(ir_functions, state_descriptors)?;
    if reads.is_empty()
        && writes.is_empty()
        && dynamic_reads.is_empty()
        && dynamic_writes.is_empty()
    {
        return Ok(None);
    }
    for key in writes.iter().cloned() {
        reads.insert(key);
    }
    Ok(Some(AccessSetHints {
        read_keys: canonical_state_hint_keys(reads.into_iter().collect()),
        write_keys: canonical_state_hint_keys(writes.into_iter().collect()),
        dynamic_reads,
        dynamic_writes,
    }))
}
fn collect_dynamic_access_hints(
    ir_functions: &[ir::Function],
    state_descriptors: &[EmbeddedStateDescriptor],
) -> Result<(Vec<DynamicAccessHint>, Vec<DynamicAccessHint>), String> {
    let state_map_key_types = state_descriptors
        .iter()
        .filter_map(|state| {
            let EmbeddedStateType::StateMap { key, .. } = &state.ty else {
                return None;
            };
            Some((state.name.as_str(), manifest_state_type_name(key)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut reads: BTreeSet<DynamicAccessHint> = BTreeSet::new();
    for function in ir_functions {
        for block in &function.blocks {
            for instruction in &block.instrs {
                let hint = match instruction {
                    ir::Instr::StateScan {
                        dynamic_access_hint: hint,
                        ..
                    } => hint,
                    _ => continue,
                };
                ivm_abi::access_hints::validate_dynamic_access_hint_v1(hint).map_err(|error| {
                    format!(
                        "K3098: optimized IR for `{}` contains invalid dynamic-access provenance `{}`: {error}",
                        function.name, hint.base_key
                    )
                })?;
                let state_name =
                    ivm_abi::access_hints::dynamic_access_hint_state_name_v1(&hint.base_key)
                        .expect("the complete V1 hint validator accepted this base key");
                let Some(expected_key_type) = state_map_key_types.get(state_name) else {
                    return Err(format!(
                        "K3098: optimized IR for `{}` contains dynamic-access provenance `{}` that does not name a declared top-level StateMap",
                        function.name, hint.base_key
                    ));
                };
                if hint.key_type != *expected_key_type {
                    return Err(format!(
                        "K3098: optimized IR for `{}` contains dynamic-access provenance `{}` with key type `{}`, but the declared StateMap key type is `{expected_key_type}`",
                        function.name, hint.base_key, hint.key_type
                    ));
                }
                reads.insert(hint.clone());
            }
        }
    }
    Ok((
        reads.into_iter().collect(),
        // V1 dynamic hints describe only bounded StateMap scans. Semantic
        // analysis rejects structural mutation of the iterated map, while
        // body writes are independent IR effects with no injective key-set
        // proof. Dynamic writes therefore remain contractually empty.
        Vec::new(),
    ))
}
fn build_message_entries(
    entries: &[super::ast::MessageEntry],
) -> Vec<iroha_data_model::smart_contract::manifest::KotobaTranslationEntry> {
    entries
        .iter()
        .map(
            |entry| iroha_data_model::smart_contract::manifest::KotobaTranslationEntry {
                msg_id: entry.msg_id.clone(),
                translations: entry
                    .translations
                    .iter()
                    .map(|translation| {
                        iroha_data_model::smart_contract::manifest::KotobaTranslation {
                            lang: translation.lang.clone(),
                            text: translation.text.clone(),
                        }
                    })
                    .collect(),
            },
        )
        .collect()
}
fn build_state_descriptors(typed: &TypedProgram) -> Result<Vec<EmbeddedStateDescriptor>, String> {
    typed
        .states
        .iter()
        .map(|state| {
            let ty = build_state_type_descriptor(&state.ty)?;
            let runtime_value_type = match &ty {
                EmbeddedStateType::StateMap { value, .. } => value.as_ref(),
                ty => ty,
            };
            if ivm_abi::state_value::admissible_state_value_schema_for_embedded_type_v1(
                runtime_value_type,
            )
            .is_none()
            {
                return Err(format!(
                    "state `{}` exceeds the exact V1 runtime StateValueSchema limit of {} nodes or levels and {} encoded bytes",
                    state.name,
                    ivm_abi::state_value::MAX_STATE_VALUE_NODES,
                    ivm_abi::state_value::MAX_STATE_VALUE_SCHEMA_BYTES,
                ));
            }
            Ok(EmbeddedStateDescriptor {
                name: state.name.clone(),
                ty,
            })
        })
        .collect()
}
fn manifest_state_descriptors(states: &[EmbeddedStateDescriptor]) -> Vec<StateDescriptor> {
    states
        .iter()
        .map(|state| StateDescriptor {
            name: state.name.clone(),
            type_name: manifest_state_type_name(&state.ty),
        })
        .collect()
}
fn manifest_state_type_name(ty: &EmbeddedStateType) -> String {
    match ty {
        EmbeddedStateType::StateCursor(key) => format!(
            "StateCursor<{}>",
            key.canonical_type_name().expect("validated map key schema")
        ),
        EmbeddedStateType::Unit => "()".to_string(),
        EmbeddedStateType::Enum(descriptor) => descriptor.identity.clone(),
        EmbeddedStateType::Error(descriptor) => descriptor.identity.clone(),
        EmbeddedStateType::Int => "int".to_string(),
        EmbeddedStateType::Decimal => "decimal".to_string(),
        EmbeddedStateType::Quantity => "quantity".to_string(),
        EmbeddedStateType::Bool => "bool".to_string(),
        EmbeddedStateType::String => "string".to_string(),
        EmbeddedStateType::Bytes => "bytes".to_string(),
        EmbeddedStateType::DataSpaceId => "DataSpaceId".to_string(),
        EmbeddedStateType::AccountId => "AccountId".to_string(),
        EmbeddedStateType::AssetDefinitionId => "AssetDefinitionId".to_string(),
        EmbeddedStateType::AssetId => "AssetId".to_string(),
        EmbeddedStateType::NftId => "NftId".to_string(),
        EmbeddedStateType::DomainId => "DomainId".to_string(),
        EmbeddedStateType::Name => "Name".to_string(),
        EmbeddedStateType::Json => "Json".to_string(),
        EmbeddedStateType::Tuple(items) => {
            let items = items
                .iter()
                .map(manifest_state_type_name)
                .collect::<Vec<_>>()
                .join(", ");
            format!("({items})")
        }
        EmbeddedStateType::Struct { name, fields } => {
            let fields = fields
                .iter()
                .map(|field| format!("{}: {}", field.name, manifest_state_type_name(&field.ty)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name}{{{fields}}}")
        }
        EmbeddedStateType::StateMap { key, value } => {
            format!(
                "StateMap<{}, {}>",
                manifest_state_type_name(key),
                manifest_state_type_name(value)
            )
        }
        EmbeddedStateType::Option(value) => {
            format!("Option<{}>", manifest_state_type_name(value))
        }
        EmbeddedStateType::Result { ok, err } => {
            format!(
                "Result<{}, {}>",
                manifest_state_type_name(ok),
                manifest_state_type_name(err)
            )
        }
        EmbeddedStateType::List { element, capacity } => {
            format!("List<{}, {capacity}>", manifest_state_type_name(element))
        }
    }
}
fn build_state_type_descriptor(ty: &semantic::Type) -> Result<EmbeddedStateType, String> {
    use semantic::Type;
    Ok(match semantic::resolve_struct_type(ty) {
        Type::Int => EmbeddedStateType::Int,
        Type::Decimal => EmbeddedStateType::Decimal,
        Type::Quantity => EmbeddedStateType::Quantity,
        Type::Bool => EmbeddedStateType::Bool,
        Type::Unit => EmbeddedStateType::Unit,
        Type::StateCursor(key) => EmbeddedStateType::StateCursor(
            crate::abi_schema::state_map_key_schema(&key)
                .ok_or_else(|| "StateCursor requires a canonical map key type".to_owned())?,
        ),
        Type::Enum(descriptor) => EmbeddedStateType::Enum((*descriptor).clone()),
        Type::ErrorEnum(descriptor) => EmbeddedStateType::Error((*descriptor).clone()),
        Type::String => EmbeddedStateType::String,
        Type::Bytes => EmbeddedStateType::Bytes,
        Type::DataSpaceId => EmbeddedStateType::DataSpaceId,
        Type::AccountId => EmbeddedStateType::AccountId,
        Type::AssetDefinitionId => EmbeddedStateType::AssetDefinitionId,
        Type::AssetId => EmbeddedStateType::AssetId,
        Type::NftId => EmbeddedStateType::NftId,
        Type::DomainId => EmbeddedStateType::DomainId,
        Type::Name => EmbeddedStateType::Name,
        Type::Json => EmbeddedStateType::Json,
        Type::Tuple(items) => EmbeddedStateType::Tuple(
            items
                .iter()
                .map(build_state_type_descriptor)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Type::Struct { name, fields } => EmbeddedStateType::Struct {
            name,
            fields: fields
                .iter()
                .map(|(field_name, field_ty)| {
                    Ok(EmbeddedStateFieldDescriptor {
                        name: field_name.clone(),
                        ty: build_state_type_descriptor(field_ty)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
        },
        Type::StateMap(key, value) => EmbeddedStateType::StateMap {
            key: Box::new(build_state_type_descriptor(&key)?),
            value: Box::new(build_state_type_descriptor(&value)?),
        },
        Type::Option(value) => {
            EmbeddedStateType::Option(Box::new(build_state_type_descriptor(&value)?))
        }
        Type::Result(ok, err) => EmbeddedStateType::Result {
            ok: Box::new(build_state_type_descriptor(&ok)?),
            err: Box::new(build_state_type_descriptor(&err)?),
        },
        Type::List(element, capacity) => EmbeddedStateType::List {
            element: Box::new(build_state_type_descriptor(&element)?),
            capacity,
        },
        Type::NamedStruct(name) => {
            return Err(format!(
                "state type `{name}` was not resolved before CNTR schema emission"
            ));
        }
        Type::ContractRef(_)
        | Type::Secret(_)
        | Type::AxtDescriptor
        | Type::AxtAnchoredSpendV1
        | Type::ProofBlob
        | Type::SoracloudRequest
        | Type::SoracloudResponse => {
            return Err("state type is not supported in embedded state schemas".to_string());
        }
    })
}
fn entrypoint_ir_symbol_name(func: &semantic::TypedFunction) -> String {
    func.name.clone()
}
fn executable_ir_roots(typed: &TypedProgram, include_tests: bool) -> BTreeSet<String> {
    typed
        .items
        .iter()
        .filter_map(|item| {
            let TypedItem::Function(function) = item;
            (function.modifiers.kind != FunctionKind::Private
                || (include_tests && function.modifiers.is_test))
                .then(|| function.name.clone())
        })
        .collect()
}
/// Declarations whose literal leaf bodies may replace an ordinary private call.
///
/// Keep this whitelist in typed HIR: SSA does not retain permission/test metadata
/// or distinguish public numeric values from secret witnesses. The full linked
/// semantic, policy and codegen validation still precedes SSA optimization.
fn private_literal_candidates(typed: &TypedProgram) -> BTreeMap<String, ir::DataRefKind> {
    typed
        .items
        .iter()
        .filter_map(|item| {
            let TypedItem::Function(function) = item;
            let crate::ast::FunctionModifiers {
                kind,
                authorization,
                is_test,
                test_fixture,
            } = &function.modifiers;
            if *kind != FunctionKind::Private
                || authorization.is_some()
                || *is_test
                || test_fixture.is_some()
                || !function.params.is_empty()
                || !function.param_types.is_empty()
            {
                return None;
            }
            let kind = match function.ret_ty.as_ref()? {
                semantic::Type::Int => ir::DataRefKind::Int,
                semantic::Type::Decimal => ir::DataRefKind::Decimal,
                semantic::Type::Quantity => ir::DataRefKind::Quantity,
                _ => return None,
            };
            Some((function.name.clone(), kind))
        })
        .collect()
}
/// Private declarations whose exact body can be moved once into one caller.
///
/// Eligibility comes from validated HIR, rather than guessing source authority
/// from SSA. Keep public roots, attributes, secrets and aggregate/state handles
/// out of this pass; the complete original source validation precedes it.
fn private_inline_candidates(typed: &TypedProgram) -> BTreeMap<String, bool> {
    fn scalar(ty: &semantic::Type) -> bool {
        matches!(
            ty,
            semantic::Type::Int
                | semantic::Type::Decimal
                | semantic::Type::Quantity
                | semantic::Type::Bool
                | semantic::Type::String
                | semantic::Type::Bytes
                | semantic::Type::DataSpaceId
                | semantic::Type::AccountId
                | semantic::Type::AssetDefinitionId
                | semantic::Type::AssetId
                | semantic::Type::NftId
                | semantic::Type::DomainId
                | semantic::Type::Name
                | semantic::Type::Json
                | semantic::Type::Unit
        )
    }
    typed
        .items
        .iter()
        .filter_map(|item| {
            let TypedItem::Function(function) = item;
            let modifiers = &function.modifiers;
            let result = function.ret_ty.as_ref().unwrap_or(&semantic::Type::Unit);
            (modifiers.kind == FunctionKind::Private
                && modifiers.authorization.is_none()
                && !modifiers.is_test
                && modifiers.test_fixture.is_none()
                && function
                    .param_types
                    .iter()
                    .all(|param| !param.is_state && scalar(&param.ty))
                && scalar(result))
            .then(|| (function.name.clone(), *result == semantic::Type::Unit))
        })
        .collect()
}
/// Scheduler-relevant access class for one lowered IR instruction.
///
/// Keeping this classification exhaustive over [`ir::Instr`] makes a newly
/// introduced host operation a compile error here instead of silently omitting
/// it from the contract's derived access metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IrAccessClass {
    /// VM-local work with no world or durable-state dependency.
    None,
    /// Contract-owned durable-state access, recorded by the state-hint pass.
    State(BuiltinAccess),
    /// Ledger/world access, recorded by the ISI-hint pass.
    Ledger(BuiltinAccess),
}
fn access_class_for_builtin(builtin: Builtin) -> IrAccessClass {
    match builtin.spec().access {
        BuiltinAccess::None => IrAccessClass::None,
        access @ (BuiltinAccess::StateRead | BuiltinAccess::StateWrite) => {
            IrAccessClass::State(access)
        }
        access @ (BuiltinAccess::LedgerRead
        | BuiltinAccess::LedgerWrite
        | BuiltinAccess::Dynamic) => IrAccessClass::Ledger(access),
    }
}
#[allow(clippy::too_many_arguments)]
fn derive_isi_access_hints(
    ir_prog: &ir::Program,
    string_map: &HashMap<(usize, ir::Temp), String>,
    authority_account_temps: &HashSet<(usize, ir::Temp)>,
    dataref_kind_map: &HashMap<(usize, ir::Temp), ir::DataRefKind>,
    instruction_literal_access_map: &HashMap<(usize, ir::Temp), AccessSets>,
    access_sets: &mut [AccessSets],
    hint_diagnostics: &mut AccessHintDiagnostics,
    hint_skips: &mut [IndexSet<String>],
) {
    for (func_idx, func) in ir_prog.functions.iter().enumerate() {
        for bb in &func.blocks {
            for instr in &bb.instrs {
                let IrAccessClass::Ledger(access) = classify_ir_access(instr) else {
                    continue;
                };
                record_isi_access(
                    instr,
                    access,
                    func_idx,
                    string_map,
                    authority_account_temps,
                    dataref_kind_map,
                    instruction_literal_access_map,
                    &mut access_sets[func_idx],
                    hint_diagnostics,
                    &mut hint_skips[func_idx],
                );
            }
        }
    }
}
fn record_hint_skip(skips: &mut IndexSet<String>, reason: &str) {
    skips.insert(reason.to_owned());
}
fn propagate_transitive_access_hints(
    ir_prog: &ir::Program,
    access_sets: &mut [AccessSets],
    hint_skips: &mut [IndexSet<String>],
) {
    assert_eq!(ir_prog.functions.len(), access_sets.len());
    assert_eq!(ir_prog.functions.len(), hint_skips.len());
    let function_by_name = ir_prog
        .functions
        .iter()
        .enumerate()
        .map(|(index, function)| (function.name.as_str(), index))
        .collect::<HashMap<_, _>>();
    let mut callees = vec![IndexSet::new(); ir_prog.functions.len()];
    let mark_conservative = |function_index: usize,
                             reason: &str,
                             access_sets: &mut [AccessSets],
                             hint_skips: &mut [IndexSet<String>]| {
        access_sets[function_index]
            .reads
            .insert(GLOBAL_WILDCARD_KEY.to_owned());
        access_sets[function_index]
            .writes
            .insert(GLOBAL_WILDCARD_KEY.to_owned());
        record_hint_skip(&mut hint_skips[function_index], reason);
    };
    for (caller_index, function) in ir_prog.functions.iter().enumerate() {
        for block in &function.blocks {
            for instruction in &block.instrs {
                match instruction {
                    ir::Instr::Call { callee, .. } | ir::Instr::CallMulti { callee, .. } => {
                        if let Some(&callee_index) = function_by_name.get(callee.as_str()) {
                            callees[caller_index].insert(callee_index);
                        } else {
                            mark_conservative(
                                caller_index,
                                HINT_SKIP_INTERNAL_CALL_TARGET,
                                access_sets,
                                hint_skips,
                            );
                        }
                    }
                    ir::Instr::CallContract { view: true, .. } => {
                        access_sets[caller_index]
                            .reads
                            .insert(GLOBAL_WILDCARD_KEY.to_owned());
                        record_hint_skip(
                            &mut hint_skips[caller_index],
                            HINT_SKIP_CONTRACT_CALL_TARGET,
                        );
                    }
                    ir::Instr::CallContract { view: false, .. }
                    | ir::Instr::InvokeEntrypointAs { .. }
                    | ir::Instr::InvokeEntrypointAsMulti { .. }
                    | ir::Instr::ExpectRejectAs { .. } => {
                        mark_conservative(
                            caller_index,
                            HINT_SKIP_CONTRACT_CALL_TARGET,
                            access_sets,
                            hint_skips,
                        );
                    }
                    _ => {}
                }
            }
        }
    }
    // Snapshot-based fixed point is deterministic and naturally handles SCCs.
    // Every iteration only adds set members, so termination is guaranteed even
    // if a malformed/pre-semantic IR graph contains recursion.
    loop {
        let access_snapshot = access_sets.to_vec();
        let skip_snapshot = hint_skips.to_vec();
        let mut changed = false;
        for caller_index in 0..ir_prog.functions.len() {
            for &callee_index in &callees[caller_index] {
                let before = (
                    access_sets[caller_index].reads.len(),
                    access_sets[caller_index].writes.len(),
                    hint_skips[caller_index].len(),
                );
                access_sets[caller_index].union_with(&access_snapshot[callee_index]);
                hint_skips[caller_index].extend(skip_snapshot[callee_index].iter().cloned());
                let after = (
                    access_sets[caller_index].reads.len(),
                    access_sets[caller_index].writes.len(),
                    hint_skips[caller_index].len(),
                );
                changed |= before != after;
            }
        }
        if !changed {
            break;
        }
    }
}
fn production_allows_incomplete_access_hints(skipped_reasons: &[String]) -> bool {
    !skipped_reasons.is_empty()
        && skipped_reasons.iter().all(|reason| {
            matches!(
                reason.as_str(),
                HINT_SKIP_CONTRACT_CALL_TARGET
                    | HINT_SKIP_DYNAMIC_STATE_PATH
                    | HINT_SKIP_DYNAMIC_INSTRUCTION_BRIDGE
                    | HINT_SKIP_OPAQUE_ISI
            )
        })
}
fn derive_state_access_hints(
    ir_prog: &ir::Program,
    state_path_hints: &HashMap<(usize, ir::Temp), StatePathHint>,
    access_sets: &mut [AccessSets],
    hint_diagnostics: &mut AccessHintDiagnostics,
    hint_skips: &mut [IndexSet<String>],
) {
    for (func_idx, func) in ir_prog.functions.iter().enumerate() {
        for bb in &func.blocks {
            for instr in &bb.instrs {
                let IrAccessClass::State(coarse_access) = classify_ir_access(instr) else {
                    continue;
                };
                match instr {
                    ir::Instr::StateGet { path, .. }
                    | ir::Instr::StateHas { path, .. }
                    | ir::Instr::StateLen { path, .. } => {
                        debug_assert_eq!(coarse_access, BuiltinAccess::StateRead);
                        if let Some(key) =
                            render_state_value_hint(state_path_hints.get(&(func_idx, *path)))
                        {
                            insert_state_hint(&mut access_sets[func_idx].reads, key);
                        } else {
                            hint_diagnostics.state_wildcards =
                                hint_diagnostics.state_wildcards.saturating_add(1);
                            record_hint_skip(
                                &mut hint_skips[func_idx],
                                HINT_SKIP_DYNAMIC_STATE_PATH,
                            );
                            access_sets[func_idx]
                                .reads
                                .insert(STATE_WILDCARD_KEY.to_string());
                        }
                    }
                    ir::Instr::StateCount { prefix, .. }
                    | ir::Instr::StateScan { base: prefix, .. } => {
                        debug_assert_eq!(coarse_access, BuiltinAccess::StateRead);
                        if let Some(key) =
                            render_state_scan_hint(state_path_hints.get(&(func_idx, *prefix)))
                        {
                            insert_state_hint(&mut access_sets[func_idx].reads, key);
                        } else {
                            hint_diagnostics.state_wildcards =
                                hint_diagnostics.state_wildcards.saturating_add(1);
                            record_hint_skip(
                                &mut hint_skips[func_idx],
                                HINT_SKIP_DYNAMIC_STATE_PATH,
                            );
                            access_sets[func_idx]
                                .reads
                                .insert(STATE_WILDCARD_KEY.to_string());
                        }
                    }
                    ir::Instr::StateSet { path, .. } | ir::Instr::StateDel { path } => {
                        debug_assert_eq!(coarse_access, BuiltinAccess::StateWrite);
                        if let Some(key) =
                            render_state_value_hint(state_path_hints.get(&(func_idx, *path)))
                        {
                            insert_state_hint(&mut access_sets[func_idx].writes, key);
                        } else {
                            hint_diagnostics.state_wildcards =
                                hint_diagnostics.state_wildcards.saturating_add(1);
                            record_hint_skip(
                                &mut hint_skips[func_idx],
                                HINT_SKIP_DYNAMIC_STATE_PATH,
                            );
                            access_sets[func_idx]
                                .reads
                                .insert(STATE_WILDCARD_KEY.to_string());
                            access_sets[func_idx]
                                .writes
                                .insert(STATE_WILDCARD_KEY.to_string());
                        }
                    }
                    _ => {
                        debug_assert!(
                            false,
                            "state-classified IR instruction is missing state-hint derivation"
                        );
                        hint_diagnostics.state_wildcards =
                            hint_diagnostics.state_wildcards.saturating_add(1);
                        record_hint_skip(&mut hint_skips[func_idx], HINT_SKIP_DYNAMIC_STATE_PATH);
                        access_sets[func_idx]
                            .reads
                            .insert(STATE_WILDCARD_KEY.to_string());
                        access_sets[func_idx]
                            .writes
                            .insert(STATE_WILDCARD_KEY.to_string());
                    }
                }
            }
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn record_isi_access(
    instr: &ir::Instr,
    coarse_access: BuiltinAccess,
    func_idx: usize,
    string_map: &HashMap<(usize, ir::Temp), String>,
    authority_account_temps: &HashSet<(usize, ir::Temp)>,
    dataref_kind_map: &HashMap<(usize, ir::Temp), ir::DataRefKind>,
    instruction_literal_access_map: &HashMap<(usize, ir::Temp), AccessSets>,
    access_set: &mut AccessSets,
    hint_diagnostics: &mut AccessHintDiagnostics,
    hint_skips: &mut IndexSet<String>,
) {
    let mut apply_fallback = |access_set: &mut AccessSets,
                              hint_diagnostics: &mut AccessHintDiagnostics,
                              reason: &str| {
        record_hint_skip(hint_skips, reason);
        hint_diagnostics.isi_wildcards = hint_diagnostics.isi_wildcards.saturating_add(1);
        if reason == HINT_SKIP_LITERAL_TRIGGER_SPEC_DECODE {
            hint_diagnostics.literal_trigger_spec_decode_failures = hint_diagnostics
                .literal_trigger_spec_decode_failures
                .saturating_add(1);
        }
        match coarse_access {
            BuiltinAccess::LedgerRead => {
                access_set.reads.insert(GLOBAL_WILDCARD_KEY.to_string());
            }
            BuiltinAccess::LedgerWrite | BuiltinAccess::Dynamic => {
                access_set.reads.insert(GLOBAL_WILDCARD_KEY.to_string());
                access_set.writes.insert(GLOBAL_WILDCARD_KEY.to_string());
            }
            BuiltinAccess::None | BuiltinAccess::StateRead | BuiltinAccess::StateWrite => {
                debug_assert!(
                    false,
                    "non-ledger IR access class reached world-access fallback"
                );
                access_set.reads.insert(GLOBAL_WILDCARD_KEY.to_string());
                access_set.writes.insert(GLOBAL_WILDCARD_KEY.to_string());
            }
        }
    };
    match instr {
        ir::Instr::TransferBatchBegin | ir::Instr::TransferBatchEnd => {}

        ir::Instr::TransferBatchAsset {
            from, to, asset, ..
        } => {
            let from =
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *from);
            let to =
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *to);
            if let Some(asset_def) = parse_temp::<AssetDefinitionId>(string_map, func_idx, *asset) {
                add_asset_rw_for_optional_account_hint(access_set, &asset_def, from.as_ref());
                add_asset_rw_for_optional_account_hint(access_set, &asset_def, to.as_ref());
            } else {
                add_dynamic_asset_definition_rw_for_optional_account_hint(
                    access_set,
                    from.as_ref(),
                );
                add_dynamic_asset_definition_rw_for_optional_account_hint(access_set, to.as_ref());
            }
        }
        ir::Instr::EscrowOpenOffer { escrow, asset, .. } => {
            let Some(escrow_id) = escrow_id_from_name_temp(string_map, func_idx, *escrow) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            let asset_definition = parse_temp::<AssetDefinitionId>(string_map, func_idx, *asset);
            record_asset_escrow_open_access(access_set, &escrow_id, asset_definition.as_ref());
        }
        ir::Instr::EscrowAccept { escrow }
        | ir::Instr::EscrowMarkPaymentSent { escrow }
        | ir::Instr::EscrowOpenDispute { escrow, .. } => {
            let Some(escrow_id) = escrow_id_from_name_temp(string_map, func_idx, *escrow) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            record_asset_escrow_lifecycle_access(access_set, &escrow_id);
        }
        ir::Instr::EscrowRelease { escrow }
        | ir::Instr::EscrowCancel { escrow }
        | ir::Instr::EscrowResolveDispute { escrow, .. } => {
            let Some(escrow_id) = escrow_id_from_name_temp(string_map, func_idx, *escrow) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            record_asset_escrow_close_access(access_set, &escrow_id);
        }
        ir::Instr::TransferAsset {
            from,
            to,
            asset,
            dataspace,
            ..
        } => {
            let from =
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *from);
            let to =
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *to);
            if let Some(asset_def) = parse_temp::<AssetDefinitionId>(string_map, func_idx, *asset) {
                if let Some(dataspace) = parse_dataspace_temp(string_map, func_idx, *dataspace) {
                    add_scoped_asset_rw_for_optional_account_hint(
                        access_set,
                        &asset_def,
                        from.as_ref(),
                        dataspace,
                    );
                    add_scoped_asset_rw_for_optional_account_hint(
                        access_set,
                        &asset_def,
                        to.as_ref(),
                        dataspace,
                    );
                } else {
                    add_asset_rw_for_optional_account_hint(access_set, &asset_def, from.as_ref());
                    add_asset_rw_for_optional_account_hint(access_set, &asset_def, to.as_ref());
                }
            } else {
                add_dynamic_asset_definition_rw_for_optional_account_hint(
                    access_set,
                    from.as_ref(),
                );
                add_dynamic_asset_definition_rw_for_optional_account_hint(access_set, to.as_ref());
            }
        }
        ir::Instr::MintAsset { account, asset, .. }
        | ir::Instr::BurnAsset { account, asset, .. } => {
            let account = account_access_hint_for_temp(
                string_map,
                authority_account_temps,
                func_idx,
                *account,
            );
            if let Some(asset_def) = parse_temp::<AssetDefinitionId>(string_map, func_idx, *asset) {
                add_asset_rw_for_optional_account_hint(access_set, &asset_def, account.as_ref());
                add_asset_def_rw(access_set, &asset_def);
            } else {
                add_dynamic_asset_definition_rw_for_optional_account_hint(
                    access_set,
                    account.as_ref(),
                );
            }
        }
        ir::Instr::RegisterDomain { domain } | ir::Instr::UnregisterDomain { domain } => {
            let Some(id) = parse_domain_temp(string_map, func_idx, *domain) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_domain_rw(access_set, &id);
        }
        ir::Instr::RegisterAccount { account } | ir::Instr::UnregisterAccount { account } => {
            let Some(id) = account_access_hint_for_temp(
                string_map,
                authority_account_temps,
                func_idx,
                *account,
            ) else {
                access_set.reads.insert(ACCOUNT_WILDCARD_KEY.to_owned());
                access_set.writes.insert(ACCOUNT_WILDCARD_KEY.to_owned());
                return;
            };
            add_account_hint_rw(access_set, &id);
        }
        ir::Instr::AddSignatory { account, .. }
        | ir::Instr::RemoveSignatory { account, .. }
        | ir::Instr::SetAccountQuorum { account, .. } => {
            let Some(id) = account_access_hint_for_temp(
                string_map,
                authority_account_temps,
                func_idx,
                *account,
            ) else {
                access_set.reads.insert(ACCOUNT_WILDCARD_KEY.to_owned());
                access_set.writes.insert(ACCOUNT_WILDCARD_KEY.to_owned());
                return;
            };
            add_account_hint_rw(access_set, &id);
        }
        ir::Instr::UnregisterAsset { asset } => {
            if let Some(id) = parse_temp::<AssetDefinitionId>(string_map, func_idx, *asset) {
                add_asset_definition_ownership_r(access_set, &id);
                add_asset_def_rw(access_set, &id);
            } else {
                add_dynamic_asset_definition_rw(access_set);
            }
        }
        ir::Instr::SetAccountDetail { account, key, .. } => {
            let (Some(id), Some(key)) = (
                account_access_hint_for_temp(
                    string_map,
                    authority_account_temps,
                    func_idx,
                    *account,
                ),
                parse_temp(string_map, func_idx, *key),
            ) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_account_detail_hint_rw(access_set, &id, &key);
        }
        ir::Instr::CreateNft { nft, owner } => {
            if let Some(owner) =
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *owner)
            {
                add_account_hint_r(access_set, &owner);
            }
            let Some(id) = parse_temp(string_map, func_idx, *nft) else {
                add_nft_coarse_rw(access_set);
                return;
            };
            add_nft_rw(access_set, &id);
        }
        ir::Instr::BurnNft { nft } => {
            let Some(id) = parse_temp(string_map, func_idx, *nft) else {
                add_nft_coarse_rw(access_set);
                return;
            };
            add_nft_rw(access_set, &id);
        }
        ir::Instr::TransferNft { from, nft, to } => {
            let (Some(from), Some(to), Some(id)) = (
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *from),
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *to),
                parse_temp(string_map, func_idx, *nft),
            ) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_account_hint_r(access_set, &from);
            add_account_hint_r(access_set, &to);
            add_nft_rw(access_set, &id);
        }
        ir::Instr::RemoveTrigger { name } | ir::Instr::SetTriggerEnabled { name, .. } => {
            let Some(id) = parse_temp(string_map, func_idx, *name) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_trigger_rw(access_set, &id);
        }
        ir::Instr::CreateRole { name, .. } | ir::Instr::DeleteRole { name } => {
            let Some(id) = parse_temp(string_map, func_idx, *name) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_role_rw(access_set, &id);
        }
        ir::Instr::GrantRole { account, name } | ir::Instr::RevokeRole { account, name } => {
            let (Some(account), Some(role)) = (
                account_access_hint_for_temp(
                    string_map,
                    authority_account_temps,
                    func_idx,
                    *account,
                ),
                parse_temp(string_map, func_idx, *name),
            ) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_account_hint_rw(access_set, &account);
            add_role_r(access_set, &role);
            add_role_binding_hint_w(access_set, &account, &role);
        }
        ir::Instr::GrantPermission { account, token }
        | ir::Instr::RevokePermission { account, token } => {
            let Some(account) = account_access_hint_for_temp(
                string_map,
                authority_account_temps,
                func_idx,
                *account,
            ) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            let Some(perm) =
                permission_name_from_token(string_map, dataref_kind_map, func_idx, *token)
            else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_account_hint_rw(access_set, &account);
            add_permission_account_hint_w(access_set, &account, &perm);
        }
        ir::Instr::GrantContractPermission { account, .. }
        | ir::Instr::RevokeContractPermission { account, .. } => {
            let Some(account) = account_access_hint_for_temp(
                string_map,
                authority_account_temps,
                func_idx,
                *account,
            ) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_account_hint_rw(access_set, &account);
            add_permission_account_hint_w(access_set, &account, "CanInvokeContractEntrypoint");
        }
        ir::Instr::RegisterAsset { asset, .. } => {
            if let Some(id) = parse_temp::<AssetDefinitionId>(string_map, func_idx, *asset) {
                add_asset_definition_ownership_r(access_set, &id);
                add_asset_def_rw(access_set, &id);
            } else {
                add_dynamic_asset_definition_rw(access_set);
            }
        }
        ir::Instr::CreateTrigger { json } => {
            let Some(raw) = string_map.get(&(func_idx, *json)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            let Some(id) = trigger_id_from_json(raw) else {
                return apply_fallback(
                    access_set,
                    hint_diagnostics,
                    HINT_SKIP_LITERAL_TRIGGER_SPEC_DECODE,
                );
            };
            add_trigger_rw(access_set, &id);
        }
        ir::Instr::VendorExecuteInstruction { payload, .. } => {
            // The emitted instruction bridge has Dynamic syscall access. Literal
            // payload hints remain useful, but cannot claim complete access for
            // that bridge: artifact admission validates the reachable syscall
            // surface independently of compiler literal propagation.
            apply_fallback(
                access_set,
                hint_diagnostics,
                HINT_SKIP_DYNAMIC_INSTRUCTION_BRIDGE,
            );
            if let Some(access) = instruction_literal_access_map.get(&(func_idx, *payload)) {
                access_set.union_with(access);
            } else if let Some(raw) = string_map.get(&(func_idx, *payload))
                && let Some(isi) = decode_instruction_box_literal(raw)
            {
                let _ = record_instruction_box_access(&isi, access_set);
            }
        }
        ir::Instr::VendorExecuteQuery { payload, .. }
        | ir::Instr::QueryExecuteNorito { payload, .. } => {
            let Some(raw) = string_map.get(&(func_idx, *payload)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            let Some(request) = decode_query_request_literal(raw) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            if record_query_request_access(&request, access_set).is_none() {
                apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            }
        }
        ir::Instr::CoreQueryGet { key, entity, .. } => {
            if record_typed_core_query_get_access(
                *key,
                *entity,
                string_map,
                authority_account_temps,
                func_idx,
                access_set,
            )
            .is_none()
            {
                apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            }
        }
        ir::Instr::CoreQueryPage { .. } | ir::Instr::QueryGet { .. } => {
            record_hint_skip(hint_skips, HINT_SKIP_OPAQUE_ISI);
            hint_diagnostics.isi_wildcards = hint_diagnostics.isi_wildcards.saturating_add(1);
            access_set.reads.insert(GLOBAL_WILDCARD_KEY.to_owned());
        }
        ir::Instr::GetAccountBalance { account, asset, .. } => {
            let account = account_access_hint_for_temp(
                string_map,
                authority_account_temps,
                func_idx,
                *account,
            );
            let asset = parse_temp::<AssetDefinitionId>(string_map, func_idx, *asset);
            match (account, asset) {
                (Some(account), Some(asset)) => {
                    add_asset_r_for_account_hint(access_set, &asset, &account);
                }
                _ => apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI),
            }
        }
        ir::Instr::ResolveAccountAlias { .. } => {
            // Alias resolution is account-scoped even when the alias is malformed or
            // not statically bound. A global world wildcard would overstate its reach.
            access_set.reads.insert(ACCOUNT_WILDCARD_KEY.to_owned());
        }
        ir::Instr::ZkVerify { .. } => {
            apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI)
        }
        ir::Instr::CreateNftsForAllUsers => {
            apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI)
        }
        ir::Instr::GetPublicInput { .. }
        | ir::Instr::GetPrivateInput { .. }
        | ir::Instr::PrivateNumericValcom { .. }
        | ir::Instr::DebugPrint { .. }
        | ir::Instr::DebugLog { .. }
        | ir::Instr::CommitOutput => {}
        ir::Instr::SmartContractLifecycle { payload, syscall } => {
            let Some(raw) = string_map.get(&(func_idx, *payload)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            if record_smart_contract_lifecycle_access(raw, *syscall, access_set).is_none() {
                apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            }
        }
        ir::Instr::ZkRootsGet { payload, .. } => {
            let Some(raw) = string_map.get(&(func_idx, *payload)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            if record_zk_roots_get_access(raw, access_set).is_none() {
                apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            }
        }
        ir::Instr::ZkVoteGetTally { payload, .. } => {
            let Some(raw) = string_map.get(&(func_idx, *payload)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            if record_zk_vote_get_tally_access(raw, access_set).is_none() {
                apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            }
        }
        ir::Instr::VrfEpochSeed { .. } => {
            // Epochs are ordinary expressions. A read-only wildcard covers the
            // exact host lookup without claiming an unrelated latest-seed read.
            apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
        }
        ir::Instr::BuildSubmitBallotInline { .. } => {}
        ir::Instr::TransferDomain { domain, to } => {
            let (Some(domain), Some(to)) = (
                parse_domain_temp(string_map, func_idx, *domain),
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, *to),
            ) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_domain_rw(access_set, &domain);
            add_account_hint_r(access_set, &to);
        }
        ir::Instr::SetNftData { nft, key, .. } => {
            let Some(id) = parse_temp(string_map, func_idx, *nft) else {
                add_nft_coarse_rw(access_set);
                return;
            };
            let Some(key) = parse_temp(string_map, func_idx, *key) else {
                add_nft_rw(access_set, &id);
                return;
            };
            add_nft_detail_rw(access_set, &id, &key);
        }
        ir::Instr::RegisterPeer { json } | ir::Instr::UnregisterPeer { json } => {
            let Some(raw) = string_map.get(&(func_idx, *json)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            let Some(peer) = peer_id_from_json_literal(raw) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_peer_rw(access_set, &peer);
        }
        ir::Instr::SubscriptionBill => add_subscription_context_rw(access_set, "bill"),
        ir::Instr::SubscriptionRecordUsage => add_subscription_context_rw(access_set, "usage"),
        ir::Instr::AxtBegin { descriptor } => {
            let Some(raw) = string_map.get(&(func_idx, *descriptor)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            let Some(descriptor) = decode_axt_descriptor_literal(raw) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_axt_descriptor_access(access_set, &descriptor);
        }
        ir::Instr::AxtTouch { dsid, manifest } => {
            let Some(dsid) = parse_dataspace_temp(string_map, func_idx, *dsid) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            if let Some(manifest) = manifest {
                let Some(raw) = string_map.get(&(func_idx, *manifest)) else {
                    return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
                };
                let Some(manifest) = decode_axt_touch_manifest_literal(raw) else {
                    return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
                };
                add_axt_touch_manifest_access(access_set, dsid, &manifest);
            } else {
                add_axt_dataspace_rw(access_set, dsid);
            }
        }
        ir::Instr::VerifyDsProof { dsid, .. } => {
            let Some(dsid) = parse_dataspace_temp(string_map, func_idx, *dsid) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            add_axt_dataspace_r(access_set, dsid);
            access_set
                .reads
                .insert(format!("axt:dataspace:{}:proof", dsid.as_u64()));
        }
        ir::Instr::StageAnchoredSpend { .. } => {
            apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
        }
        ir::Instr::AxtCommit => {}
        ir::Instr::SoracloudHostCall {
            request, syscall, ..
        } => {
            let Some(raw) = string_map.get(&(func_idx, *request)) else {
                return apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            };
            if record_soracloud_request_access(raw, *syscall, access_set).is_none() {
                apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI);
            }
        }
        ir::Instr::CallContract { .. } => {
            apply_fallback(access_set, hint_diagnostics, HINT_SKIP_CONTRACT_CALL_TARGET)
        }
        ir::Instr::InvokeEntrypointAs { .. }
        | ir::Instr::InvokeEntrypointAsMulti { .. }
        | ir::Instr::ExpectRejectAs { .. }
        | ir::Instr::ActorAccount { .. }
        | ir::Instr::ActorPublicKey { .. }
        | ir::Instr::ActorSign { .. } => {
            apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI)
        }
        _ => apply_fallback(access_set, hint_diagnostics, HINT_SKIP_OPAQUE_ISI),
    }
}
fn decode_norito_literal_payload(raw: &str) -> Option<Vec<u8>> {
    // `DataKind::NoritoBytes` wraps these exact source bytes in the emitted
    // pointer TLV. Access analysis must inspect that exact payload: unwrapping a
    // source-level TLV here would analyze an inner frame that the host never
    // receives.
    decode_hex_or_raw_bytes(raw).ok()
}
fn decode_instruction_box_literal(raw: &str) -> Option<InstructionBox> {
    let payload = decode_norito_literal_payload(raw)?;
    ivm_abi::codec::decode_canonical_norito(&payload).ok()
}
fn access_for_instruction_literal(raw: &str) -> Option<AccessSets> {
    let instr = decode_instruction_box_literal(raw)?;
    let mut access = AccessSets::default();
    record_instruction_box_access(&instr, &mut access)?;
    Some(access)
}
fn decode_query_request_literal(raw: &str) -> Option<QueryRequest> {
    let payload = decode_norito_literal_payload(raw)?;
    ivm_abi::codec::decode_canonical_norito(&payload).ok()
}
fn record_zk_roots_get_access(raw: &str, access_set: &mut AccessSets) -> Option<()> {
    let payload = decode_norito_literal_payload(raw)?;
    let request: ivm_abi::host_payload::RootsGetRequest =
        ivm_abi::codec::decode_canonical_norito(&payload).ok()?;
    let asset = request.asset_id.parse().ok()?;
    add_zk_asset_r(access_set, &asset);
    Some(())
}
fn record_zk_vote_get_tally_access(raw: &str, access_set: &mut AccessSets) -> Option<()> {
    let payload = decode_norito_literal_payload(raw)?;
    let request: ivm_abi::host_payload::VoteGetTallyRequest =
        ivm_abi::codec::decode_canonical_norito(&payload).ok()?;
    add_zk_election_tally_r(access_set, &request.election_id);
    Some(())
}
fn record_smart_contract_lifecycle_access(
    raw: &str,
    syscall: u32,
    access_set: &mut AccessSets,
) -> Option<()> {
    use iroha_data_model::isi::smart_contract_code as DMScode;
    let payload = decode_norito_literal_payload(raw)?;
    match syscall {
        syscalls::SYSCALL_REGISTER_SMART_CONTRACT_CODE => {
            let request: DMScode::RegisterSmartContractCode =
                ivm_abi::codec::decode_canonical_norito(&payload).ok()?;
            if request.manifest.code_hash != Some(request.artifact_id.code_hash) {
                return None;
            }
            add_contract_code_r(access_set, &request.artifact_id);
            add_contract_manifest_rw(access_set, &request.artifact_id);
        }
        syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES => {
            let request: DMScode::RegisterSmartContractBytes =
                ivm_abi::codec::decode_canonical_norito(&payload).ok()?;
            add_contract_code_rw(access_set, &request.artifact_id);
        }
        syscalls::SYSCALL_ACTIVATE_CONTRACT_INSTANCE => {
            let request: DMScode::ActivateContractInstance =
                ivm_abi::codec::decode_canonical_norito(&payload).ok()?;
            let artifact_id = iroha_data_model::smart_contract::ContractArtifactId::new(
                request.contract_address.dataspace_id().ok()?,
                request.code_hash,
            );
            add_contract_code_r(access_set, &artifact_id);
            add_contract_manifest_r(access_set, &artifact_id);
            add_contract_instance_rw(access_set, &request.contract_address);
            add_contract_instance_code_hash_rw(access_set, &artifact_id);
        }
        syscalls::SYSCALL_REMOVE_SMART_CONTRACT_BYTES => {
            let request: DMScode::RemoveSmartContractBytes =
                ivm_abi::codec::decode_canonical_norito(&payload).ok()?;
            add_contract_code_rw(access_set, &request.artifact_id);
            add_contract_manifest_r(access_set, &request.artifact_id);
            add_contract_instance_code_hash_r(access_set, &request.artifact_id);
        }
        _ => return None,
    }
    Some(())
}
fn record_transfer_asset_batch_entries_access(
    batch: &iroha_data_model::isi::transfer::TransferAssetBatch,
    access_set: &mut AccessSets,
) -> Option<()> {
    if batch.entries().is_empty() {
        return None;
    }
    for entry in batch.entries() {
        let source = AssetId::of(entry.asset_definition().clone(), entry.from().clone());
        let destination = AssetId::of(entry.asset_definition().clone(), entry.to().clone());
        add_asset_rw(access_set, &source);
        add_asset_rw(access_set, &destination);
    }
    Some(())
}
fn decode_axt_descriptor_literal(raw: &str) -> Option<crate::axt::AxtDescriptor> {
    let bytes = decode_hex_or_raw_bytes(raw).ok()?;
    let descriptor = ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
    crate::axt::validate_descriptor(&descriptor).ok()?;
    Some(descriptor)
}
fn decode_axt_touch_manifest_literal(raw: &str) -> Option<crate::axt::TouchManifest> {
    let payload = decode_norito_literal_payload(raw)?;
    let manifest = ivm_abi::codec::decode_canonical_norito(&payload).ok()?;
    crate::axt::validate_touch_manifest(&manifest).ok()?;
    Some(manifest)
}
fn parse_dataspace_temp(
    string_map: &HashMap<(usize, ir::Temp), String>,
    func_idx: usize,
    temp: ir::Temp,
) -> Option<iroha_model_base::topology::DataSpaceId> {
    let raw = string_map.get(&(func_idx, temp))?;
    if let Some(raw_id) = parse_u64_literal(raw) {
        return Some(iroha_model_base::topology::DataSpaceId::new(raw_id));
    }
    let bytes = decode_hex_or_raw_bytes(raw).ok()?;
    ivm_abi::codec::decode_canonical_norito(&bytes).ok()
}
fn public_key_from_json_value(value: &json::Value) -> Option<iroha_crypto::PublicKey> {
    if let Some(key_str) = value.as_str() {
        return key_str.parse().ok();
    }
    let map = value.as_object()?;
    let value = map
        .get("public_key")
        .or_else(|| map.get("publicKey"))
        .or_else(|| map.get("key"))?;
    public_key_from_json_value(value)
}
fn peer_id_from_json_value(value: &json::Value) -> Option<iroha_model_base::peer::PeerId> {
    if let Some(peer_str) = value.as_str() {
        if let Ok(peer_id) = peer_str.parse::<iroha_model_base::peer::PeerId>() {
            return Some(peer_id);
        }
        if let Ok(peer) = peer_str.parse::<iroha_data_model::peer::Peer>() {
            return Some(peer.id().clone());
        }
        return None;
    }
    let map = value.as_object()?;
    if let Some(value) = map
        .get("peer")
        .or_else(|| map.get("peer_id"))
        .or_else(|| map.get("peerId"))
    {
        return peer_id_from_json_value(value);
    }
    let key = map
        .get("public_key")
        .or_else(|| map.get("publicKey"))
        .or_else(|| map.get("key"))?;
    public_key_from_json_value(key).map(iroha_model_base::peer::PeerId::from)
}
fn peer_id_from_json_literal(raw: &str) -> Option<iroha_model_base::peer::PeerId> {
    let value: json::Value = json::from_slice(raw.as_bytes()).ok()?;
    peer_id_from_json_value(&value)
}
fn record_soracloud_request_access(
    raw: &str,
    syscall: u32,
    access_set: &mut AccessSets,
) -> Option<()> {
    use iroha_data_model::soracloud::{
        SoracloudHostOperationV1 as Op, SoracloudHostRequestEnvelopeV1,
        SoracloudHostRequestPayloadV1 as Payload,
    };
    let bytes = decode_hex_or_raw_bytes(raw).ok()?;
    let request: SoracloudHostRequestEnvelopeV1 =
        ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
    request.validate().ok()?;
    let expected = soracloud_operation_for_syscall(syscall)?;
    if request.operation != expected {
        return None;
    }
    match (&request.operation, &request.payload) {
        (Op::ReadCommittedState, Payload::ReadCommittedState(payload)) => {
            add_soracloud_state_r(access_set, &payload.binding_name, &payload.state_key);
        }
        (Op::EmitStateMutation, Payload::EmitStateMutation(payload)) => {
            add_soracloud_state_rw(access_set, &payload.binding_name, &payload.state_key);
        }
        (Op::EmitMailboxMessage, Payload::EmitMailboxMessage(payload)) => {
            access_set.writes.insert(format!(
                "soracloud:mailbox:{}:{}",
                payload.to_service, payload.to_handler
            ));
        }
        (Op::AppendJournal, Payload::AppendJournal(payload)) => {
            access_set.writes.insert(format!(
                "soracloud:journal:{}",
                soracloud_host_path_key_segment(&payload.artifact_path)
            ));
        }
        (Op::PublishCheckpoint, Payload::PublishCheckpoint(payload)) => {
            access_set.writes.insert(format!(
                "soracloud:checkpoint:{}",
                soracloud_host_path_key_segment(&payload.artifact_path)
            ));
        }
        (Op::ReadConfig, Payload::ReadConfig(payload)) => {
            access_set
                .reads
                .insert(format!("soracloud:config:{}", payload.config_name));
        }
        (Op::ReadSecretEnvelope, Payload::ReadSecretEnvelope(payload)) => {
            access_set
                .reads
                .insert(format!("soracloud:secret_envelope:{}", payload.secret_name));
        }
        _ => return None,
    }
    Some(())
}
fn soracloud_host_path_key_segment(path: &str) -> &str {
    path.strip_prefix('/').unwrap_or(path)
}
fn soracloud_operation_for_syscall(
    syscall: u32,
) -> Option<iroha_data_model::soracloud::SoracloudHostOperationV1> {
    use iroha_data_model::soracloud::SoracloudHostOperationV1 as Op;
    match syscall {
        syscalls::SYSCALL_SORACLOUD_READ_COMMITTED_STATE => Some(Op::ReadCommittedState),
        syscalls::SYSCALL_SORACLOUD_EMIT_STATE_MUTATION => Some(Op::EmitStateMutation),
        syscalls::SYSCALL_SORACLOUD_EMIT_MAILBOX_MESSAGE => Some(Op::EmitMailboxMessage),
        syscalls::SYSCALL_SORACLOUD_APPEND_JOURNAL => Some(Op::AppendJournal),
        syscalls::SYSCALL_SORACLOUD_PUBLISH_CHECKPOINT => Some(Op::PublishCheckpoint),
        syscalls::SYSCALL_SORACLOUD_READ_CONFIG => Some(Op::ReadConfig),
        syscalls::SYSCALL_SORACLOUD_READ_SECRET_ENVELOPE => Some(Op::ReadSecretEnvelope),
        _ => None,
    }
}
#[allow(clippy::too_many_arguments)]
fn submit_ballot_inline_instruction_literal(
    string_map: &HashMap<(usize, ir::Temp), String>,
    func_idx: usize,
    election_id: ir::Temp,
    ciphertext: ir::Temp,
    nullifier: ir::Temp,
    backend: ir::Temp,
    proof: ir::Temp,
    vk: ir::Temp,
) -> Option<String> {
    use iroha_data_model::{
        isi::zk as DMZk,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
    };
    let literal = |temp| string_map.get(&(func_idx, temp)).cloned();
    let eid = literal(election_id)?;
    if !iroha_data_model::governance::is_valid_governance_selector_v1(&eid) {
        return None;
    }
    let backend_str = literal(backend)?;
    let ct_bytes = decode_hex_or_raw_bytes(&literal(ciphertext)?).ok()?;
    let nf_bytes = decode_hex_or_raw_bytes(&literal(nullifier)?).ok()?;
    let null32: [u8; 32] = nf_bytes.try_into().ok()?;
    let proof_bytes = decode_hex_or_raw_bytes(&literal(proof)?).ok()?;
    let vk_ref = literal(vk)?;
    let ballot_proof = ProofAttachment::new_ref(
        backend_str.clone(),
        ProofBox::new(backend_str.clone(), proof_bytes),
        VerifyingKeyId::new(backend_str, vk_ref),
    );
    let submit = DMZk::SubmitBallot {
        election_id: eid,
        ciphertext: ct_bytes,
        ballot_proof,
        nullifier: null32,
    };
    let boxed = InstructionBox::from(submit);
    let bytes = ivm_abi::codec::encode_canonical_norito(&boxed).ok()?;
    Some(format!("0x{}", hex::encode(bytes)))
}
fn record_instruction_box_access(
    instr: &InstructionBox,
    access_set: &mut AccessSets,
) -> Option<()> {
    let any = instr.as_any();
    if any.downcast_ref::<Log>().is_some() {
        return Some(());
    }
    if let Some(instr) = any.downcast_ref::<iroha_data_model::isi::zk::CreateElection>() {
        add_zk_election_w(access_set, instr.election_id());
        return Some(());
    }
    if let Some(instr) = any.downcast_ref::<iroha_data_model::isi::zk::SubmitBallot>() {
        add_zk_election_submit_w(access_set, instr.election_id());
        return Some(());
    }
    if let Some(instr) = any.downcast_ref::<iroha_data_model::isi::zk::FinalizeElection>() {
        add_zk_election_tally_w(access_set, instr.election_id());
        return Some(());
    }
    if let Some(instr) = any.downcast_ref::<iroha_data_model::isi::transfer::TransferAssetBatch>() {
        return record_transfer_asset_batch_entries_access(instr, access_set);
    }
    {
        use iroha_data_model::isi::escrow as DMEscrow;
        if let Some(instr) = any.downcast_ref::<DMEscrow::OpenAssetEscrow>() {
            record_asset_escrow_open_access(
                access_set,
                &instr.escrow_id,
                Some(&instr.asset_definition),
            );
            return Some(());
        }
        if let Some(instr) = any.downcast_ref::<DMEscrow::AcceptAssetEscrow>() {
            record_asset_escrow_lifecycle_access(access_set, &instr.escrow_id);
            return Some(());
        }
        if let Some(instr) = any.downcast_ref::<DMEscrow::MarkEscrowPaymentSent>() {
            record_asset_escrow_lifecycle_access(access_set, &instr.escrow_id);
            return Some(());
        }
        if let Some(instr) = any.downcast_ref::<DMEscrow::ReleaseAssetEscrow>() {
            record_asset_escrow_close_access(access_set, &instr.escrow_id);
            return Some(());
        }
        if let Some(instr) = any.downcast_ref::<DMEscrow::CancelAssetEscrow>() {
            record_asset_escrow_close_access(access_set, &instr.escrow_id);
            return Some(());
        }
        if let Some(instr) = any.downcast_ref::<DMEscrow::OpenEscrowDispute>() {
            record_asset_escrow_lifecycle_access(access_set, &instr.escrow_id);
            return Some(());
        }
        if let Some(instr) = any.downcast_ref::<DMEscrow::ResolveEscrowDispute>() {
            record_asset_escrow_close_access(access_set, &instr.escrow_id);
            return Some(());
        }
    }
    if let Some(tb) = any.downcast_ref::<TransferBox>() {
        match tb {
            TransferBox::Asset(t) => {
                let src = t.source.clone();
                let dst = AssetId::of(t.source.definition.clone(), t.destination.clone());
                add_asset_rw(access_set, &src);
                add_asset_rw(access_set, &dst);
            }
            TransferBox::Domain(t) => {
                add_domain_rw(access_set, &t.object);
                add_account_r(access_set, &t.source);
                add_account_r(access_set, &t.destination);
            }
            TransferBox::AssetDefinition(t) => {
                add_asset_def_rw(access_set, &t.object);
                add_account_r(access_set, &t.source);
                add_account_r(access_set, &t.destination);
            }
            TransferBox::Nft(t) => {
                add_nft_rw(access_set, &t.object);
                add_account_r(access_set, &t.source);
                add_account_r(access_set, &t.destination);
            }
        }
        return Some(());
    }
    if let Some(mb) = any.downcast_ref::<MintBox>() {
        match mb {
            MintBox::Asset(m) => {
                add_asset_rw(access_set, &m.destination);
                add_asset_def_rw(access_set, m.destination.definition());
            }
            MintBox::TriggerRepetitions(m) => {
                add_trigger_rw(access_set, &m.destination);
            }
        }
        return Some(());
    }
    if let Some(bb) = any.downcast_ref::<BurnBox>() {
        match bb {
            BurnBox::Asset(b) => {
                add_asset_rw(access_set, &b.destination);
                add_asset_def_rw(access_set, b.destination.definition());
            }
            BurnBox::TriggerRepetitions(b) => {
                add_trigger_rw(access_set, &b.destination);
            }
        }
        return Some(());
    }
    if let Some(sb) = any.downcast_ref::<SetKeyValueBox>() {
        match sb {
            SetKeyValueBox::Account(s) => {
                add_account_detail_rw(access_set, &s.object, &s.key);
            }
            SetKeyValueBox::Domain(s) => {
                add_domain_detail_rw(access_set, &s.object, &s.key);
            }
            SetKeyValueBox::AssetDefinition(s) => {
                add_asset_def_detail_rw(access_set, &s.object, &s.key);
            }
            SetKeyValueBox::Nft(s) => {
                add_nft_detail_rw(access_set, &s.object, &s.key);
            }
            SetKeyValueBox::Trigger(s) => {
                access_set.reads.insert(key_trigger(&s.object));
                access_set
                    .writes
                    .insert(key_trigger_detail(&s.object, &s.key));
            }
        }
        return Some(());
    }
    if let Some(rb) = any.downcast_ref::<RemoveKeyValueBox>() {
        match rb {
            RemoveKeyValueBox::Account(r) => {
                add_account_detail_rw(access_set, &r.object, &r.key);
            }
            RemoveKeyValueBox::Domain(r) => {
                add_domain_detail_rw(access_set, &r.object, &r.key);
            }
            RemoveKeyValueBox::AssetDefinition(r) => {
                add_asset_def_detail_rw(access_set, &r.object, &r.key);
            }
            RemoveKeyValueBox::Nft(r) => {
                add_nft_detail_rw(access_set, &r.object, &r.key);
            }
            RemoveKeyValueBox::Trigger(r) => {
                access_set.reads.insert(key_trigger(&r.object));
                access_set
                    .writes
                    .insert(key_trigger_detail(&r.object, &r.key));
            }
        }
        return Some(());
    }
    if let Some(rb) = any.downcast_ref::<RegisterBox>() {
        match rb {
            RegisterBox::Domain(r) => add_domain_rw(access_set, r.object.id()),
            RegisterBox::Account(r) => {
                add_account_rw(access_set, r.object.id());
            }
            RegisterBox::AssetDefinition(r) => {
                if let Some(domain_id) = r.object.owning_domain.as_ref() {
                    add_domain_r(access_set, domain_id);
                }
                add_asset_def_rw(access_set, r.object.id());
            }
            RegisterBox::Nft(r) => add_nft_rw(access_set, r.object.id()),
            RegisterBox::Peer(_) => return None,
            RegisterBox::Trigger(r) => add_trigger_rw(access_set, r.object.id()),
            RegisterBox::Role(r) => add_role_rw(access_set, r.object.id()),
        }
        return Some(());
    }
    if let Some(ub) = any.downcast_ref::<UnregisterBox>() {
        match ub {
            UnregisterBox::Domain(u) => add_domain_rw(access_set, &u.object),
            UnregisterBox::Account(u) => add_account_rw(access_set, &u.object),
            UnregisterBox::AssetDefinition(u) => add_asset_def_rw(access_set, &u.object),
            UnregisterBox::Nft(u) => add_nft_rw(access_set, &u.object),
            UnregisterBox::Peer(_) => return None,
            UnregisterBox::Trigger(u) => add_trigger_rw(access_set, &u.object),
            UnregisterBox::Role(u) => add_role_rw(access_set, &u.object),
        }
        return Some(());
    }
    if let Some(gb) = any.downcast_ref::<GrantBox>() {
        match gb {
            GrantBox::Permission(g) => {
                add_account_rw(access_set, &g.destination);
                add_permission_account_w(access_set, &g.destination, g.object.name());
            }
            GrantBox::Role(g) => {
                add_account_rw(access_set, &g.destination);
                add_role_r(access_set, &g.object);
                add_role_binding_w(access_set, &g.destination, &g.object);
            }
            GrantBox::RolePermission(g) => {
                add_role_rw(access_set, &g.destination);
                add_permission_role_w(access_set, &g.destination, g.object.name());
            }
        }
        return Some(());
    }
    if let Some(rb) = any.downcast_ref::<RevokeBox>() {
        match rb {
            RevokeBox::Permission(r) => {
                add_account_rw(access_set, &r.destination);
                add_permission_account_w(access_set, &r.destination, r.object.name());
            }
            RevokeBox::Role(r) => {
                add_account_rw(access_set, &r.destination);
                add_role_r(access_set, &r.object);
                add_role_binding_w(access_set, &r.destination, &r.object);
            }
            RevokeBox::RolePermission(r) => {
                add_role_rw(access_set, &r.destination);
                add_permission_role_w(access_set, &r.destination, r.object.name());
            }
        }
        return Some(());
    }
    if let Some(exe) = any.downcast_ref::<ExecuteTrigger>() {
        access_set.reads.insert(key_trigger(&exe.trigger));
        access_set
            .writes
            .insert(key_trigger_repetitions(&exe.trigger));
        return Some(());
    }
    None
}
fn record_query_request_access(request: &QueryRequest, access_set: &mut AccessSets) -> Option<()> {
    match request {
        QueryRequest::Singular(query) => record_singular_query_access(query, access_set),
        QueryRequest::Start(_) | QueryRequest::Continue(_) => None,
    }
}
fn record_singular_query_access(
    query: &SingularQueryBox,
    access_set: &mut AccessSets,
) -> Option<()> {
    match query {
        SingularQueryBox::FindAssetById(q) => {
            add_asset_r(access_set, q.asset_id());
            Some(())
        }
        SingularQueryBox::FindAssetDefinitionById(q) => {
            add_asset_def_r(access_set, q.asset_definition_id());
            Some(())
        }
        SingularQueryBox::FindNftById(q) => {
            add_nft_r(access_set, q.nft_id());
            Some(())
        }
        _ => None,
    }
}
fn record_typed_core_query_get_access(
    key: ir::Temp,
    entity: ivm_abi::core_query::CoreQueryEntityTagV1,
    string_map: &HashMap<(usize, ir::Temp), String>,
    authority_account_temps: &HashSet<(usize, ir::Temp)>,
    func_idx: usize,
    access_set: &mut AccessSets,
) -> Option<()> {
    use ivm_abi::core_query::CoreQueryEntityTagV1;
    match entity {
        CoreQueryEntityTagV1::Account => {
            let account =
                account_access_hint_for_temp(string_map, authority_account_temps, func_idx, key)?;
            add_account_hint_r(access_set, &account);
            Some(())
        }
        CoreQueryEntityTagV1::Asset => {
            let id = parse_temp::<AssetId>(string_map, func_idx, key)?;
            add_asset_r(access_set, &id);
            Some(())
        }
        CoreQueryEntityTagV1::AssetDefinition => {
            let id = parse_temp::<AssetDefinitionId>(string_map, func_idx, key)?;
            add_asset_def_r(access_set, &id);
            Some(())
        }
        CoreQueryEntityTagV1::Domain => {
            let id = parse_domain_temp(string_map, func_idx, key)?;
            add_domain_r(access_set, &id);
            Some(())
        }
        CoreQueryEntityTagV1::Nft => {
            let id = parse_temp::<NftId>(string_map, func_idx, key)?;
            add_nft_r(access_set, &id);
            Some(())
        }
    }
}
trait ParseTempLiteral: Sized {
    fn parse_temp_literal(raw: &str) -> Option<Self>;
}
impl<T: std::str::FromStr> ParseTempLiteral for T {
    fn parse_temp_literal(raw: &str) -> Option<Self> {
        raw.parse().ok()
    }
}
fn parse_temp<T: ParseTempLiteral>(
    string_map: &HashMap<(usize, ir::Temp), String>,
    func_idx: usize,
    temp: ir::Temp,
) -> Option<T> {
    T::parse_temp_literal(string_map.get(&(func_idx, temp))?)
}
fn escrow_id_from_name_temp(
    string_map: &HashMap<(usize, ir::Temp), String>,
    func_idx: usize,
    temp: ir::Temp,
) -> Option<EscrowId> {
    parse_temp::<Name>(string_map, func_idx, temp).map(|name| EscrowId::from_kotodama_name(&name))
}
fn parse_domain_temp(
    string_map: &HashMap<(usize, ir::Temp), String>,
    func_idx: usize,
    temp: ir::Temp,
) -> Option<iroha_model_base::domain::DomainId> {
    iroha_model_base::domain::DomainId::parse_fully_qualified(string_map.get(&(func_idx, temp))?)
        .ok()
}
fn parse_account_temp(
    string_map: &HashMap<(usize, ir::Temp), String>,
    func_idx: usize,
    temp: ir::Temp,
) -> Option<AccountId> {
    AccountId::parse_encoded(string_map.get(&(func_idx, temp))?).ok()
}
fn collect_function_return_literal_facts(
    ir_prog: &ir::Program,
    string_map: &HashMap<(usize, ir::Temp), String>,
    dataref_kind_map: &HashMap<(usize, ir::Temp), ir::DataRefKind>,
    string_literal_temps: &HashSet<(usize, ir::Temp)>,
) -> HashMap<String, LiteralPointerFact> {
    let mut out = HashMap::new();
    for (func_idx, func) in ir_prog.functions.iter().enumerate() {
        let mut reachable = HashSet::new();
        let mut stack = vec![func.entry];
        while let Some(label) = stack.pop() {
            if !reachable.insert(label) {
                continue;
            }
            let Some(bb) = func.blocks.iter().find(|bb| bb.label == label) else {
                continue;
            };
            match &bb.terminator {
                ir::Terminator::Jump(next) => stack.push(*next),
                ir::Terminator::Branch {
                    then_bb, else_bb, ..
                } => {
                    stack.push(*then_bb);
                    stack.push(*else_bb);
                }
                ir::Terminator::Return(_)
                | ir::Terminator::Return2(_, _)
                | ir::Terminator::ReturnN(_) => {}
            }
        }
        let mut fact: Option<LiteralPointerFact> = None;
        let mut saw_return = false;
        let mut incompatible = false;
        for bb in &func.blocks {
            if !reachable.contains(&bb.label) {
                continue;
            }
            match &bb.terminator {
                ir::Terminator::Return(Some(temp)) => {
                    saw_return = true;
                    let key = (func_idx, *temp);
                    let Some(raw) = string_map.get(&key).cloned() else {
                        incompatible = true;
                        break;
                    };
                    let Some(kind) = dataref_kind_map.get(&key).copied() else {
                        incompatible = true;
                        break;
                    };
                    let candidate = LiteralPointerFact {
                        raw,
                        kind,
                        is_string_literal: string_literal_temps.contains(&key),
                    };
                    match &fact {
                        Some(existing) if existing != &candidate => {
                            incompatible = true;
                            break;
                        }
                        Some(_) => {}
                        None => fact = Some(candidate),
                    }
                }
                ir::Terminator::Return(None)
                | ir::Terminator::Return2(_, _)
                | ir::Terminator::ReturnN(_) => {
                    incompatible = true;
                    break;
                }
                ir::Terminator::Jump(_) | ir::Terminator::Branch { .. } => {}
            }
        }
        if saw_return
            && !incompatible
            && let Some(fact) = fact
        {
            out.insert(func.name.clone(), fact);
        }
    }
    out
}
fn propagate_function_return_literal_facts(
    ir_prog: &ir::Program,
    string_map: &mut HashMap<(usize, ir::Temp), String>,
    dataref_kind_map: &mut HashMap<(usize, ir::Temp), ir::DataRefKind>,
    string_literal_temps: &mut HashSet<(usize, ir::Temp)>,
    multiply_defined_dests: &HashSet<(usize, ir::Temp)>,
) {
    loop {
        let facts = collect_function_return_literal_facts(
            ir_prog,
            string_map,
            dataref_kind_map,
            string_literal_temps,
        );
        if facts.is_empty() {
            return;
        }
        let mut changed = false;
        for (func_idx, func) in ir_prog.functions.iter().enumerate() {
            for bb in &func.blocks {
                for instr in &bb.instrs {
                    let Some((callee, dest)) = (match instr {
                        ir::Instr::Call {
                            callee,
                            dest: Some(dest),
                            ..
                        } => Some((callee.as_str(), *dest)),
                        _ => None,
                    }) else {
                        continue;
                    };
                    let Some(fact) = facts.get(callee) else {
                        continue;
                    };
                    let dest_key = (func_idx, dest);
                    if multiply_defined_dests.contains(&dest_key) {
                        continue;
                    }
                    if string_map.get(&dest_key) != Some(&fact.raw) {
                        string_map.insert(dest_key, fact.raw.clone());
                        changed = true;
                    }
                    if dataref_kind_map.get(&dest_key).copied() != Some(fact.kind) {
                        dataref_kind_map.insert(dest_key, fact.kind);
                        changed = true;
                    }
                    if fact.is_string_literal {
                        changed |= string_literal_temps.insert(dest_key);
                    } else {
                        changed |= string_literal_temps.remove(&dest_key);
                    }
                }
            }
        }
        changed |= propagate_literal_copy_facts(
            ir_prog,
            string_map,
            dataref_kind_map,
            string_literal_temps,
            multiply_defined_dests,
        );
        if !changed {
            return;
        }
    }
}
fn propagate_literal_copy_facts(
    ir_prog: &ir::Program,
    string_map: &mut HashMap<(usize, ir::Temp), String>,
    dataref_kind_map: &mut HashMap<(usize, ir::Temp), ir::DataRefKind>,
    string_literal_temps: &mut HashSet<(usize, ir::Temp)>,
    multiply_defined_dests: &HashSet<(usize, ir::Temp)>,
) -> bool {
    let mut changed = false;
    for (func_idx, func) in ir_prog.functions.iter().enumerate() {
        for bb in &func.blocks {
            for instr in &bb.instrs {
                let ir::Instr::Copy { dest, src } = instr else {
                    continue;
                };
                if dest == src {
                    continue;
                }
                let dest_key = (func_idx, *dest);
                if multiply_defined_dests.contains(&dest_key) {
                    continue;
                }
                let src_key = (func_idx, *src);
                let Some(raw) = string_map.get(&src_key).cloned() else {
                    continue;
                };
                let Some(kind) = dataref_kind_map.get(&src_key).copied() else {
                    continue;
                };
                if string_map.get(&dest_key) != Some(&raw) {
                    string_map.insert(dest_key, raw);
                    changed = true;
                }
                if dataref_kind_map.get(&dest_key).copied() != Some(kind) {
                    dataref_kind_map.insert(dest_key, kind);
                    changed = true;
                }
                if string_literal_temps.contains(&src_key) {
                    changed |= string_literal_temps.insert(dest_key);
                } else {
                    changed |= string_literal_temps.remove(&dest_key);
                }
            }
        }
    }
    changed
}
fn account_access_hint_for_temp(
    string_map: &HashMap<(usize, ir::Temp), String>,
    authority_account_temps: &HashSet<(usize, ir::Temp)>,
    func_idx: usize,
    temp: ir::Temp,
) -> Option<AccountAccessHint> {
    if authority_account_temps.contains(&(func_idx, temp)) {
        return Some(AccountAccessHint::Authority);
    }
    parse_account_temp(string_map, func_idx, temp).map(AccountAccessHint::Literal)
}
fn permission_name_from_token(
    string_map: &HashMap<(usize, ir::Temp), String>,
    dataref_kind_map: &HashMap<(usize, ir::Temp), ir::DataRefKind>,
    func_idx: usize,
    temp: ir::Temp,
) -> Option<String> {
    let raw = string_map.get(&(func_idx, temp))?;
    match dataref_kind_map.get(&(func_idx, temp))? {
        ir::DataRefKind::Name => Some(permission_name_from_literal(raw)),
        ir::DataRefKind::Json => permission_name_from_json(raw),
        _ => None,
    }
}
fn permission_name_from_literal(raw: &str) -> String {
    raw.split_once(':')
        .map(|(name, _)| name)
        .unwrap_or(raw)
        .to_string()
}
fn permission_name_from_json(raw: &str) -> Option<String> {
    let value: norito::json::Value = norito::json::from_slice(raw.as_bytes()).ok()?;
    if let Some(name) = value.as_str() {
        return Some(permission_name_from_literal(name));
    }
    let map = value.as_object()?;
    let kind = map.get("type").and_then(norito::json::Value::as_str)?;
    Some(permission_name_from_literal(kind))
}
fn trigger_id_from_json(raw: &str) -> Option<TriggerId> {
    let value: json::Value = json::from_slice(raw.as_bytes()).ok()?;
    match value {
        json::Value::String(encoded) => {
            let bytes = STANDARD.decode(encoded.as_bytes()).ok()?;
            let trigger: Trigger = ivm_abi::codec::decode_canonical_norito(&bytes).ok()?;
            Some(trigger.id().clone())
        }
        json::Value::Object(map) => {
            let id = map.get("id")?.as_str()?;
            id.parse().ok()
        }
        _ => None,
    }
}
fn key_account(id: &AccountId) -> String {
    format!("account:{id}")
}
fn key_account_hint(account: &AccountAccessHint) -> String {
    match account {
        AccountAccessHint::Literal(id) => key_account(id),
        AccountAccessHint::Authority => AUTHORITY_ACCOUNT_KEY.to_owned(),
    }
}
fn key_domain(id: &DomainId) -> String {
    format!("domain:{id}")
}
fn key_asset_def(id: &AssetDefinitionId) -> String {
    format!("asset_def:{id}")
}
fn key_escrow_id(id: &EscrowId) -> String {
    format!("escrow_id:{}", hex::encode(id.as_hash().as_ref()))
}
fn key_asset_escrow(id: &EscrowId) -> String {
    format!("asset_escrow:{}", hex::encode(id.as_hash().as_ref()))
}
fn key_asset(id: &AssetId) -> String {
    format!("asset:{id}")
}
fn key_asset_for_account_hint(
    definition: &AssetDefinitionId,
    account: &AccountAccessHint,
) -> String {
    match account {
        AccountAccessHint::Literal(account) => {
            key_asset(&AssetId::of(definition.clone(), account.clone()))
        }
        AccountAccessHint::Authority => format!("asset:{definition}:{AUTHORITY_PLACEHOLDER}"),
    }
}
fn key_scoped_asset_for_account_hint(
    definition: &AssetDefinitionId,
    account: &AccountAccessHint,
    dataspace: iroha_model_base::topology::DataSpaceId,
) -> String {
    match account {
        AccountAccessHint::Literal(account) => key_asset(&AssetId::with_scope(
            definition.clone(),
            account.clone(),
            AssetBalanceScope::Dataspace(dataspace),
        )),
        AccountAccessHint::Authority => {
            format!("asset:{definition}:{AUTHORITY_PLACEHOLDER}:dataspace:{dataspace}")
        }
    }
}
fn key_nft(id: &NftId) -> String {
    format!("nft:{id}")
}
fn key_role(id: &RoleId) -> String {
    format!("role:{id}")
}
fn key_role_binding(account: &AccountId, role: &RoleId) -> String {
    format!("role.binding:{account}:{role}")
}
fn key_role_binding_hint(account: &AccountAccessHint, role: &RoleId) -> String {
    match account {
        AccountAccessHint::Literal(account) => key_role_binding(account, role),
        AccountAccessHint::Authority => format!("role.binding:{AUTHORITY_PLACEHOLDER}:{role}"),
    }
}
fn key_perm_account(account: &AccountId, perm: &str) -> String {
    format!("perm.account:{account}:{perm}")
}
fn key_perm_account_hint(account: &AccountAccessHint, perm: &str) -> String {
    match account {
        AccountAccessHint::Literal(account) => key_perm_account(account, perm),
        AccountAccessHint::Authority => format!("perm.account:{AUTHORITY_PLACEHOLDER}:{perm}"),
    }
}
fn key_perm_role(role: &RoleId, perm: &str) -> String {
    format!("perm.role:{role}:{perm}")
}
fn key_trigger(id: &TriggerId) -> String {
    format!("trigger:{id}")
}
fn key_trigger_repetitions(id: &TriggerId) -> String {
    format!("trigger.repetitions:{id}")
}
fn key_trigger_detail(id: &TriggerId, key: &Name) -> String {
    format!("trigger.detail:{id}:{key}")
}
fn key_account_detail(id: &AccountId, key: &Name) -> String {
    format!("account.detail:{id}:{key}")
}
fn key_domain_detail(id: &DomainId, key: &Name) -> String {
    format!("domain.detail:{id}:{key}")
}
fn key_asset_def_detail(id: &AssetDefinitionId, key: &Name) -> String {
    format!("asset_def.detail:{id}:{key}")
}
fn key_zk_asset(id: &AssetDefinitionId) -> String {
    format!("zk_asset:{id}")
}
fn key_peer(id: &iroha_model_base::peer::PeerId) -> String {
    format!("peer:{id}")
}
fn key_contract_manifest(
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) -> String {
    format!(
        "contract.manifest:{}:{}",
        artifact_id.dataspace_id.as_u64(),
        artifact_id.code_hash
    )
}
fn key_contract_code(artifact_id: &iroha_data_model::smart_contract::ContractArtifactId) -> String {
    format!(
        "contract.code:{}:{}",
        artifact_id.dataspace_id.as_u64(),
        artifact_id.code_hash
    )
}
fn key_contract_instance(address: &iroha_data_model::smart_contract::ContractAddress) -> String {
    format!("contract.instance:{address}")
}
fn key_contract_instance_code_hash(
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) -> String {
    format!(
        "contract.instance.code_hash:{}:{}",
        artifact_id.dataspace_id.as_u64(),
        artifact_id.code_hash
    )
}
fn key_nft_detail(id: &NftId, key: &Name) -> String {
    format!("nft.detail:{id}:{key}")
}
fn add_account_r(set: &mut AccessSets, id: &AccountId) {
    set.reads.insert(ACCOUNT_WILDCARD_KEY.to_string());
    set.reads.insert(key_account(id));
}
fn add_account_hint_r(set: &mut AccessSets, account: &AccountAccessHint) {
    set.reads.insert(key_account_hint(account));
}
fn add_domain_r(set: &mut AccessSets, id: &DomainId) {
    set.reads.insert(key_domain(id));
}
fn add_account_rw(set: &mut AccessSets, id: &AccountId) {
    set.reads.insert(ACCOUNT_WILDCARD_KEY.to_string());
    set.writes.insert(ACCOUNT_WILDCARD_KEY.to_string());
    let key = key_account(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_account_hint_rw(set: &mut AccessSets, account: &AccountAccessHint) {
    let key = key_account_hint(account);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_account_detail_rw(set: &mut AccessSets, id: &AccountId, key: &Name) {
    add_account_r(set, id);
    let detail = key_account_detail(id, key);
    set.reads.insert(detail.clone());
    set.writes.insert(detail);
}
fn add_account_detail_hint_rw(set: &mut AccessSets, account: &AccountAccessHint, key: &Name) {
    add_account_hint_r(set, account);
    let detail = match account {
        AccountAccessHint::Literal(id) => key_account_detail(id, key),
        AccountAccessHint::Authority => format!("account.detail:{AUTHORITY_PLACEHOLDER}:{key}"),
    };
    set.reads.insert(detail.clone());
    set.writes.insert(detail);
}
fn add_domain_rw(set: &mut AccessSets, id: &DomainId) {
    let key = key_domain(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_domain_detail_rw(set: &mut AccessSets, id: &DomainId, key: &Name) {
    add_domain_r(set, id);
    let detail = key_domain_detail(id, key);
    set.reads.insert(detail.clone());
    set.writes.insert(detail);
}
fn add_asset_def_rw(set: &mut AccessSets, id: &AssetDefinitionId) {
    set.reads.insert(ASSET_DEF_WILDCARD_KEY.to_string());
    set.writes.insert(ASSET_DEF_WILDCARD_KEY.to_string());
    let key = key_asset_def(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_asset_def_r(set: &mut AccessSets, id: &AssetDefinitionId) {
    set.reads.insert(ASSET_DEF_WILDCARD_KEY.to_string());
    set.reads.insert(key_asset_def(id));
}
fn add_asset_definition_ownership_r(set: &mut AccessSets, id: &AssetDefinitionId) {
    add_asset_def_r(set, id);
}
fn add_asset_r(set: &mut AccessSets, id: &AssetId) {
    set.reads.insert(key_asset(id));
    add_account_r(set, id.account());
    add_asset_definition_ownership_r(set, id.definition());
    add_asset_def_r(set, id.definition());
}
fn add_asset_r_for_account_hint(
    set: &mut AccessSets,
    definition: &AssetDefinitionId,
    account: &AccountAccessHint,
) {
    set.reads
        .insert(key_asset_for_account_hint(definition, account));
    add_account_hint_r(set, account);
    add_asset_definition_ownership_r(set, definition);
    add_asset_def_r(set, definition);
}
fn add_asset_def_detail_rw(set: &mut AccessSets, id: &AssetDefinitionId, key: &Name) {
    add_asset_def_r(set, id);
    let detail = key_asset_def_detail(id, key);
    set.reads.insert(detail.clone());
    set.writes.insert(detail);
}
fn add_zk_asset_r(set: &mut AccessSets, id: &AssetDefinitionId) {
    set.reads.insert(key_zk_asset(id));
}
fn add_escrow_id_rw(set: &mut AccessSets, id: &EscrowId) {
    let key = key_escrow_id(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_asset_escrow_rw(set: &mut AccessSets, id: &EscrowId) {
    add_escrow_id_rw(set, id);
    let key = key_asset_escrow(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_peer_rw(set: &mut AccessSets, id: &iroha_model_base::peer::PeerId) {
    let key = key_peer(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_contract_manifest_r(
    set: &mut AccessSets,
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) {
    set.reads.insert(key_contract_manifest(artifact_id));
}
fn add_contract_manifest_rw(
    set: &mut AccessSets,
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) {
    let key = key_contract_manifest(artifact_id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_contract_code_r(
    set: &mut AccessSets,
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) {
    set.reads.insert(key_contract_code(artifact_id));
}
fn add_contract_code_rw(
    set: &mut AccessSets,
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) {
    let key = key_contract_code(artifact_id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_contract_instance_rw(
    set: &mut AccessSets,
    address: &iroha_data_model::smart_contract::ContractAddress,
) {
    let key = key_contract_instance(address);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_contract_instance_code_hash_r(
    set: &mut AccessSets,
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) {
    set.reads
        .insert(key_contract_instance_code_hash(artifact_id));
}
fn add_contract_instance_code_hash_rw(
    set: &mut AccessSets,
    artifact_id: &iroha_data_model::smart_contract::ContractArtifactId,
) {
    let key = key_contract_instance_code_hash(artifact_id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_zk_election_w(set: &mut AccessSets, election_id: &str) {
    set.writes.insert(format!("zk:election:{election_id}"));
}
fn add_zk_election_submit_w(set: &mut AccessSets, election_id: &str) {
    set.writes
        .insert(format!("zk:election:{election_id}:ciphertexts"));
    set.writes
        .insert(format!("zk:election:{election_id}:nullifiers"));
}
fn add_zk_election_tally_w(set: &mut AccessSets, election_id: &str) {
    set.writes
        .insert(format!("zk:election:{election_id}:tally"));
}
fn add_zk_election_tally_r(set: &mut AccessSets, election_id: &str) {
    set.reads.insert(format!("zk:election:{election_id}:tally"));
}
fn add_asset_rw(set: &mut AccessSets, id: &AssetId) {
    set.reads.insert(ASSET_WILDCARD_KEY.to_string());
    set.writes.insert(ASSET_WILDCARD_KEY.to_string());
    let key = key_asset(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
    add_account_r(set, id.account());
    add_asset_definition_ownership_r(set, id.definition());
    add_asset_def_r(set, id.definition());
}
fn add_asset_rw_for_account_hint(
    set: &mut AccessSets,
    definition: &AssetDefinitionId,
    account: &AccountAccessHint,
) {
    set.reads.insert(ASSET_WILDCARD_KEY.to_string());
    set.writes.insert(ASSET_WILDCARD_KEY.to_string());
    let key = key_asset_for_account_hint(definition, account);
    set.reads.insert(key.clone());
    set.writes.insert(key);
    add_account_hint_r(set, account);
    add_asset_definition_ownership_r(set, definition);
    add_asset_def_r(set, definition);
}
fn add_scoped_asset_rw_for_account_hint(
    set: &mut AccessSets,
    definition: &AssetDefinitionId,
    account: &AccountAccessHint,
    dataspace: iroha_model_base::topology::DataSpaceId,
) {
    set.reads.insert(ASSET_WILDCARD_KEY.to_string());
    set.writes.insert(ASSET_WILDCARD_KEY.to_string());
    let key = key_scoped_asset_for_account_hint(definition, account, dataspace);
    set.reads.insert(key.clone());
    set.writes.insert(key);
    add_account_hint_r(set, account);
    add_asset_definition_ownership_r(set, definition);
    add_asset_def_r(set, definition);
}
fn add_dynamic_asset_account_rw(set: &mut AccessSets, definition: &AssetDefinitionId) {
    set.reads.insert(ASSET_WILDCARD_KEY.to_string());
    set.writes.insert(ASSET_WILDCARD_KEY.to_string());
    set.reads.insert(ACCOUNT_WILDCARD_KEY.to_string());
    add_asset_definition_ownership_r(set, definition);
    add_asset_def_rw(set, definition);
}
fn add_dynamic_asset_definition_rw(set: &mut AccessSets) {
    set.reads.insert(ASSET_WILDCARD_KEY.to_string());
    set.writes.insert(ASSET_WILDCARD_KEY.to_string());
    set.reads.insert(ASSET_DEF_WILDCARD_KEY.to_string());
    set.writes.insert(ASSET_DEF_WILDCARD_KEY.to_string());
}
fn add_dynamic_asset_definition_rw_for_optional_account_hint(
    set: &mut AccessSets,
    account: Option<&AccountAccessHint>,
) {
    add_dynamic_asset_definition_rw(set);
    if let Some(account) = account {
        add_account_hint_r(set, account);
    } else {
        set.reads.insert(ACCOUNT_WILDCARD_KEY.to_string());
    }
}
fn add_asset_rw_for_optional_account_hint(
    set: &mut AccessSets,
    definition: &AssetDefinitionId,
    account: Option<&AccountAccessHint>,
) {
    if let Some(account) = account {
        add_asset_rw_for_account_hint(set, definition, account);
    } else {
        add_dynamic_asset_account_rw(set, definition);
    }
}
fn add_scoped_asset_rw_for_optional_account_hint(
    set: &mut AccessSets,
    definition: &AssetDefinitionId,
    account: Option<&AccountAccessHint>,
    dataspace: iroha_model_base::topology::DataSpaceId,
) {
    if let Some(account) = account {
        add_scoped_asset_rw_for_account_hint(set, definition, account, dataspace);
    } else {
        add_dynamic_asset_account_rw(set, definition);
    }
}
fn add_nft_rw(set: &mut AccessSets, id: &NftId) {
    add_nft_coarse_rw(set);
    let key = key_nft(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_nft_r(set: &mut AccessSets, id: &NftId) {
    set.reads.insert(NFT_COARSE_KEY.to_string());
    set.reads.insert(key_nft(id));
}
fn add_nft_coarse_rw(set: &mut AccessSets) {
    set.reads.insert(NFT_COARSE_KEY.to_string());
    set.writes.insert(NFT_COARSE_KEY.to_string());
}
fn add_nft_detail_rw(set: &mut AccessSets, id: &NftId, key: &Name) {
    add_nft_rw(set, id);
    let detail = key_nft_detail(id, key);
    set.reads.insert(detail.clone());
    set.writes.insert(detail);
}
fn add_role_rw(set: &mut AccessSets, id: &RoleId) {
    let key = key_role(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_role_r(set: &mut AccessSets, id: &RoleId) {
    set.reads.insert(key_role(id));
}
fn add_role_binding_w(set: &mut AccessSets, account: &AccountId, role: &RoleId) {
    set.writes.insert(key_role_binding(account, role));
}
fn add_role_binding_hint_w(set: &mut AccessSets, account: &AccountAccessHint, role: &RoleId) {
    set.writes.insert(key_role_binding_hint(account, role));
}
fn add_permission_account_w(set: &mut AccessSets, account: &AccountId, perm: &str) {
    set.writes.insert(key_perm_account(account, perm));
}
fn add_permission_account_hint_w(set: &mut AccessSets, account: &AccountAccessHint, perm: &str) {
    set.writes.insert(key_perm_account_hint(account, perm));
}
fn add_permission_role_w(set: &mut AccessSets, role: &RoleId, perm: &str) {
    set.writes.insert(key_perm_role(role, perm));
}
fn add_subscription_context_rw(set: &mut AccessSets, kind: &str) {
    let key = format!("subscription:trigger_context:{kind}");
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_soracloud_state_r(set: &mut AccessSets, binding: &Name, state_key: &str) {
    set.reads.insert(format!(
        "soracloud:state:{binding}:{}",
        soracloud_host_path_key_segment(state_key)
    ));
}
fn add_soracloud_state_rw(set: &mut AccessSets, binding: &Name, state_key: &str) {
    let key = format!(
        "soracloud:state:{binding}:{}",
        soracloud_host_path_key_segment(state_key)
    );
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn axt_dataspace_key(dsid: iroha_model_base::topology::DataSpaceId) -> String {
    format!("axt:dataspace:{}", dsid.as_u64())
}
fn add_axt_dataspace_r(set: &mut AccessSets, dsid: iroha_model_base::topology::DataSpaceId) {
    set.reads.insert(axt_dataspace_key(dsid));
}
fn add_axt_dataspace_rw(set: &mut AccessSets, dsid: iroha_model_base::topology::DataSpaceId) {
    let key = axt_dataspace_key(dsid);
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_axt_touch_key_r(
    set: &mut AccessSets,
    dsid: iroha_model_base::topology::DataSpaceId,
    key: &str,
) {
    add_axt_dataspace_r(set, dsid);
    set.reads
        .insert(format!("axt:dataspace:{}:{key}", dsid.as_u64()));
}
fn add_axt_touch_key_rw(
    set: &mut AccessSets,
    dsid: iroha_model_base::topology::DataSpaceId,
    key: &str,
) {
    add_axt_dataspace_rw(set, dsid);
    let key = format!("axt:dataspace:{}:{key}", dsid.as_u64());
    set.reads.insert(key.clone());
    set.writes.insert(key);
}
fn add_axt_touch_manifest_access(
    set: &mut AccessSets,
    dsid: iroha_model_base::topology::DataSpaceId,
    manifest: &crate::axt::TouchManifest,
) {
    add_axt_dataspace_rw(set, dsid);
    for key in &manifest.read {
        add_axt_touch_key_r(set, dsid, key);
    }
    for key in &manifest.write {
        add_axt_touch_key_rw(set, dsid, key);
    }
}
fn add_axt_descriptor_access(set: &mut AccessSets, descriptor: &crate::axt::AxtDescriptor) {
    for dsid in &descriptor.dsids {
        add_axt_dataspace_rw(set, *dsid);
    }
    for touch in &descriptor.touches {
        add_axt_dataspace_rw(set, touch.dsid);
        for key in &touch.read {
            add_axt_touch_key_r(set, touch.dsid, key);
        }
        for key in &touch.write {
            add_axt_touch_key_rw(set, touch.dsid, key);
        }
    }
}
fn add_trigger_rw(set: &mut AccessSets, id: &TriggerId) {
    let key = key_trigger(id);
    set.reads.insert(key.clone());
    set.writes.insert(key);
    set.writes.insert(key_trigger_repetitions(id));
}
fn record_asset_escrow_open_access(
    set: &mut AccessSets,
    escrow_id: &EscrowId,
    asset_definition: Option<&AssetDefinitionId>,
) {
    add_asset_escrow_rw(set, escrow_id);
    set.reads.insert(ACCOUNT_WILDCARD_KEY.to_string());
    set.writes.insert(ACCOUNT_WILDCARD_KEY.to_string());
    if let Some(asset_definition) = asset_definition {
        add_asset_definition_ownership_r(set, asset_definition);
        add_asset_rw_for_account_hint(set, asset_definition, &AccountAccessHint::Authority);
        add_dynamic_asset_account_rw(set, asset_definition);
    } else {
        add_dynamic_asset_definition_rw_for_optional_account_hint(
            set,
            Some(&AccountAccessHint::Authority),
        );
    }
}
fn record_asset_escrow_lifecycle_access(set: &mut AccessSets, escrow_id: &EscrowId) {
    add_asset_escrow_rw(set, escrow_id);
}
fn record_asset_escrow_close_access(set: &mut AccessSets, escrow_id: &EscrowId) {
    add_asset_escrow_rw(set, escrow_id);
    add_dynamic_asset_definition_rw(set);
}
fn classify_ir_access(instr: &ir::Instr) -> IrAccessClass {
    match instr {
        ir::Instr::Source(_) => IrAccessClass::None,
        ir::Instr::Const { .. }
        | ir::Instr::Copy { .. }
        | ir::Instr::StringConst { .. }
        | ir::Instr::Binary { .. }
        | ir::Instr::WrappingBinary { .. }
        | ir::Instr::Unary { .. }
        | ir::Instr::WrappingNeg { .. }
        | ir::Instr::IntFromI64 { .. }
        | ir::Instr::IntFromU64 { .. }
        | ir::Instr::IntToI64 { .. }
        | ir::Instr::IntToU64 { .. }
        | ir::Instr::NumericConvert { .. }
        | ir::Instr::NumericTryConvert { .. }
        | ir::Instr::NumericStatus { .. }
        | ir::Instr::NumericNeg { .. }
        | ir::Instr::NumericBinary { .. }
        | ir::Instr::NumericRound { .. }
        | ir::Instr::DecimalToInt { .. }
        | ir::Instr::NumericCompare { .. }
        | ir::Instr::Min { .. }
        | ir::Instr::Max { .. }
        | ir::Instr::Abs { .. }
        | ir::Instr::DivCeil { .. }
        | ir::Instr::Gcd { .. }
        | ir::Instr::Mean { .. }
        | ir::Instr::Isqrt { .. }
        | ir::Instr::LoadVar { .. }
        | ir::Instr::Poseidon2 { .. }
        | ir::Instr::Poseidon6 { .. }
        | ir::Instr::Pubkgen { .. }
        | ir::Instr::Valcom { .. }
        | ir::Instr::AssertEq { .. }
        | ir::Instr::Assert { .. }
        | ir::Instr::AbortIf { .. }
        | ir::Instr::MapNew { .. }
        | ir::Instr::PointerFromString { .. }
        | ir::Instr::MapGet { .. }
        | ir::Instr::MapLoadPair { .. }
        | ir::Instr::MapSet { .. }
        | ir::Instr::Load64Imm { .. }
        | ir::Instr::Load64 { .. }
        | ir::Instr::Store64Imm { .. }
        | ir::Instr::Store64 { .. }
        | ir::Instr::TuplePack { .. }
        | ir::Instr::TupleGet { .. }
        | ir::Instr::Call { .. }
        | ir::Instr::CallMulti { .. }
        | ir::Instr::DataRef { .. }
        | ir::Instr::GetAuthority { .. }
        | ir::Instr::SysvarAuthority { .. }
        | ir::Instr::CurrentTimeMs { .. }
        | ir::Instr::BlockHeight { .. }
        | ir::Instr::BlockTimeMs { .. }
        | ir::Instr::ChainId { .. }
        | ir::Instr::ContractAddress { .. }
        | ir::Instr::Entrypoint { .. }
        | ir::Instr::GetTriggerEvent { .. }
        | ir::Instr::GetPublicInput { .. }
        | ir::Instr::StateMapKeyAt { .. }
        | ir::Instr::StateValueEncode { .. }
        | ir::Instr::StatePathFromName { .. }
        | ir::Instr::PathMapKeyNorito { .. }
        | ir::Instr::PointerToNorito { .. }
        | ir::Instr::PointerFromNorito { .. }
        | ir::Instr::JsonEncode { .. }
        | ir::Instr::JsonDecode { .. }
        | ir::Instr::TlvLen { .. }
        | ir::Instr::JsonObject { .. }
        | ir::Instr::JsonSetInt { .. }
        | ir::Instr::JsonSetAccountId { .. }
        | ir::Instr::JsonGetNumeric { .. }
        | ir::Instr::JsonGetJson { .. }
        | ir::Instr::JsonGetName { .. }
        | ir::Instr::JsonGetAccountId { .. }
        | ir::Instr::JsonGetAssetDefinitionId { .. }
        | ir::Instr::JsonGetNftId { .. }
        | ir::Instr::JsonGetBlobHex { .. }
        | ir::Instr::JsonGetString { .. }
        | ir::Instr::JsonGetBool { .. }
        | ir::Instr::NameDecode { .. }
        | ir::Instr::SchemaEncode { .. }
        | ir::Instr::SchemaDecode { .. }
        | ir::Instr::SchemaInfo { .. }
        | ir::Instr::PointerEq { .. } => IrAccessClass::None,
        ir::Instr::Sm3Hash { .. } => access_class_for_builtin(Builtin::Sm3Hash),
        ir::Instr::Sha256Hash { .. } => access_class_for_builtin(Builtin::Sha256Hash),
        ir::Instr::Sha3Hash { .. } => access_class_for_builtin(Builtin::Sha3Hash),
        ir::Instr::Blake2b256Hash { .. } => access_class_for_builtin(Builtin::Blake2b256Hash),
        ir::Instr::Keccak256Hash { .. } => access_class_for_builtin(Builtin::Keccak256Hash),
        ir::Instr::IrohaHash { .. } => access_class_for_builtin(Builtin::IrohaHash),
        ir::Instr::Sm2Verify { .. } => access_class_for_builtin(Builtin::Sm2Verify),
        ir::Instr::VerifySignature { .. } => access_class_for_builtin(Builtin::VerifySignature),
        ir::Instr::Sm4GcmSeal { .. } => access_class_for_builtin(Builtin::Sm4GcmSeal),
        ir::Instr::Sm4GcmOpen { .. } => access_class_for_builtin(Builtin::Sm4GcmOpen),
        ir::Instr::Sm4CcmSeal { .. } => access_class_for_builtin(Builtin::Sm4CcmSeal),
        ir::Instr::Sm4CcmOpen { .. } => access_class_for_builtin(Builtin::Sm4CcmOpen),
        ir::Instr::PrivateNumericValcom { .. } => access_class_for_builtin(Builtin::Valcom),
        ir::Instr::RegisterAsset { .. } => access_class_for_builtin(Builtin::RegisterAsset),
        ir::Instr::TransferAsset { .. } => access_class_for_builtin(Builtin::TransferAsset),
        ir::Instr::TransferBatchAsset { .. } => access_class_for_builtin(Builtin::TransferBatch),
        ir::Instr::EscrowOpenOffer { .. } => access_class_for_builtin(Builtin::EscrowOpenOffer),
        ir::Instr::EscrowAccept { .. } => access_class_for_builtin(Builtin::EscrowAccept),
        ir::Instr::EscrowMarkPaymentSent { .. } => {
            access_class_for_builtin(Builtin::EscrowMarkPaymentSent)
        }
        ir::Instr::EscrowRelease { .. } => access_class_for_builtin(Builtin::EscrowRelease),
        ir::Instr::EscrowCancel { .. } => access_class_for_builtin(Builtin::EscrowCancel),
        ir::Instr::EscrowOpenDispute { .. } => access_class_for_builtin(Builtin::EscrowOpenDispute),
        ir::Instr::EscrowResolveDispute { .. } => {
            access_class_for_builtin(Builtin::EscrowResolveDispute)
        }
        ir::Instr::TransferBatchBegin | ir::Instr::TransferBatchEnd => {
            access_class_for_builtin(Builtin::TransferBatch)
        }
        ir::Instr::MintAsset { .. } => access_class_for_builtin(Builtin::MintAsset),
        ir::Instr::BurnAsset { .. } => access_class_for_builtin(Builtin::BurnAsset),
        ir::Instr::Info { .. } => access_class_for_builtin(Builtin::Info),
        ir::Instr::DebugPrint { .. } => access_class_for_builtin(Builtin::DebugPrint),
        ir::Instr::DebugLog { .. } => access_class_for_builtin(Builtin::DebugLog),
        ir::Instr::CreateNftsForAllUsers => {
            access_class_for_builtin(Builtin::CreateNftsForAllUsers)
        }
        ir::Instr::SetExecutionDepth { .. } => access_class_for_builtin(Builtin::SetExecutionDepth),
        ir::Instr::SetVl { .. } => access_class_for_builtin(Builtin::SetVl),
        ir::Instr::SetAccountDetail { .. } => access_class_for_builtin(Builtin::SetAccountMetadata),
        ir::Instr::CreateNft { .. } => access_class_for_builtin(Builtin::NftMintAsset),
        ir::Instr::SetNftData { .. } => access_class_for_builtin(Builtin::NftSetMetadata),
        ir::Instr::BurnNft { .. } => access_class_for_builtin(Builtin::NftBurnAsset),
        ir::Instr::TransferNft { .. } => access_class_for_builtin(Builtin::NftTransferAsset),
        ir::Instr::RegisterDomain { .. } => access_class_for_builtin(Builtin::RegisterDomain),
        ir::Instr::RegisterAccount { .. } => access_class_for_builtin(Builtin::RegisterAccount),
        ir::Instr::AddSignatory { .. } => access_class_for_builtin(Builtin::AddSignatory),
        ir::Instr::RemoveSignatory { .. } => access_class_for_builtin(Builtin::RemoveSignatory),
        ir::Instr::SetAccountQuorum { .. } => access_class_for_builtin(Builtin::SetAccountQuorum),
        ir::Instr::UnregisterDomain { .. } => access_class_for_builtin(Builtin::UnregisterDomain),
        ir::Instr::UnregisterAsset { .. } => access_class_for_builtin(Builtin::UnregisterAsset),
        ir::Instr::UnregisterAccount { .. } => access_class_for_builtin(Builtin::UnregisterAccount),
        ir::Instr::RegisterPeer { .. } => access_class_for_builtin(Builtin::RegisterPeer),
        ir::Instr::UnregisterPeer { .. } => access_class_for_builtin(Builtin::UnregisterPeer),
        ir::Instr::CreateTrigger { .. } => access_class_for_builtin(Builtin::RegisterTrigger),
        ir::Instr::RemoveTrigger { .. } => access_class_for_builtin(Builtin::UnregisterTrigger),
        ir::Instr::SetTriggerEnabled { .. } => access_class_for_builtin(Builtin::SetTriggerEnabled),
        ir::Instr::GrantPermission { .. } => access_class_for_builtin(Builtin::GrantPermission),
        ir::Instr::RevokePermission { .. } => access_class_for_builtin(Builtin::RevokePermission),
        ir::Instr::GrantContractPermission { .. } => {
            access_class_for_builtin(Builtin::GrantContractPermission)
        }
        ir::Instr::RevokeContractPermission { .. } => {
            access_class_for_builtin(Builtin::RevokeContractPermission)
        }
        ir::Instr::CreateRole { .. } => access_class_for_builtin(Builtin::RegisterRole),
        ir::Instr::DeleteRole { .. } => access_class_for_builtin(Builtin::UnregisterRole),
        ir::Instr::GrantRole { .. } => access_class_for_builtin(Builtin::GrantRole),
        // Host-private local-test helpers (assertion reports, block height and time control)
        // touch only the test host, never ledger state; they exist only in test projections.
        ir::Instr::DirectHelperSyscall { syscall, .. }
            if ivm_abi::syscalls::is_koto_test_syscall(*syscall) =>
        {
            IrAccessClass::None
        }
        ir::Instr::DirectHelperSyscall { syscall, .. } => {
            use ivm_abi::syscalls::SyscallAccess;
            match ivm_abi::syscalls::registered_syscall_access(*syscall) {
                Some(SyscallAccess::None) => IrAccessClass::None,
                Some(SyscallAccess::StateRead) => IrAccessClass::Ledger(BuiltinAccess::StateRead),
                Some(SyscallAccess::StateWrite) => IrAccessClass::Ledger(BuiltinAccess::StateWrite),
                Some(SyscallAccess::LedgerRead) => IrAccessClass::Ledger(BuiltinAccess::LedgerRead),
                Some(SyscallAccess::LedgerWrite) => {
                    IrAccessClass::Ledger(BuiltinAccess::LedgerWrite)
                }
                Some(SyscallAccess::Dynamic) | None => {
                    IrAccessClass::Ledger(BuiltinAccess::Dynamic)
                }
            }
        }
        ir::Instr::RevokeRole { .. } => access_class_for_builtin(Builtin::RevokeRole),
        ir::Instr::TransferDomain { .. } => access_class_for_builtin(Builtin::TransferDomain),
        ir::Instr::ResolveAccountAlias { .. } => {
            access_class_for_builtin(Builtin::ResolveAccountAlias)
        }
        ir::Instr::CallContract { view, .. } => IrAccessClass::Ledger(if *view {
            BuiltinAccess::LedgerRead
        } else {
            BuiltinAccess::Dynamic
        }),
        ir::Instr::InvokeEntrypointAs { .. } | ir::Instr::InvokeEntrypointAsMulti { .. } => {
            access_class_for_builtin(Builtin::TestInvokeEntrypointAs)
        }
        ir::Instr::ExpectRejectAs { .. } => access_class_for_builtin(Builtin::TestExpectRejectAs),
        ir::Instr::ActorAccount { .. } => access_class_for_builtin(Builtin::TestActorAccount),
        ir::Instr::ActorPublicKey { .. } => access_class_for_builtin(Builtin::TestActorPublicKey),
        ir::Instr::ActorSign { .. } => access_class_for_builtin(Builtin::TestActorSign),
        ir::Instr::ZkVerify { number, .. } => match *number {
            ivm_abi::syscalls::SYSCALL_ZK_VERIFY_BATCH => {
                access_class_for_builtin(Builtin::ZkVerifyBatch)
            }
            ivm_abi::syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT => {
                access_class_for_builtin(Builtin::ZkVoteVerifyBallot)
            }
            ivm_abi::syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY => {
                access_class_for_builtin(Builtin::ZkVoteVerifyTally)
            }
            _ => IrAccessClass::Ledger(BuiltinAccess::Dynamic),
        },
        ir::Instr::ExecutionSummary { .. } => access_class_for_builtin(Builtin::ExecutionSummary),
        ir::Instr::GrowHeap { .. } => access_class_for_builtin(Builtin::GrowHeap),
        ir::Instr::GetMerklePath { .. } => access_class_for_builtin(Builtin::GetMerklePath),
        ir::Instr::GetMerkleCompact { .. } => access_class_for_builtin(Builtin::GetMerkleCompact),
        ir::Instr::GetRegisterMerkleCompact { .. } => {
            access_class_for_builtin(Builtin::GetRegisterMerkleCompact)
        }
        ir::Instr::VerifyProof { .. } => access_class_for_builtin(Builtin::VerifyProof),
        ir::Instr::VendorExecuteInstruction { kind, .. } => access_class_for_builtin(match kind {
            ir::VendorInstructionKind::SubmitBallot => Builtin::ScExecuteSubmitBallot,
        }),
        ir::Instr::VendorExecuteQuery { .. } => access_class_for_builtin(Builtin::ExecuteQuery),
        ir::Instr::QueryExecuteNorito { .. } => {
            access_class_for_builtin(Builtin::QueryExecuteNorito)
        }
        ir::Instr::QueryGet { .. } => access_class_for_builtin(Builtin::QueryGetParameter),
        ir::Instr::CoreQueryGet { .. } => access_class_for_builtin(Builtin::QueryGetAccount),
        ir::Instr::CoreQueryPage { .. } => access_class_for_builtin(Builtin::QueryPageAccounts),
        ir::Instr::GetAccountBalance { .. } => access_class_for_builtin(Builtin::GetAccountBalance),
        ir::Instr::Alloc { .. } => access_class_for_builtin(Builtin::Alloc),
        ir::Instr::GetPrivateInput { .. } => access_class_for_builtin(Builtin::GetPrivateInput),
        ir::Instr::CommitOutput => access_class_for_builtin(Builtin::CommitOutput),
        ir::Instr::SmartContractLifecycle { syscall, .. } => match *syscall {
            ivm_abi::syscalls::SYSCALL_DEACTIVATE_CONTRACT_INSTANCE => {
                access_class_for_builtin(Builtin::DeactivateContractInstance)
            }
            ivm_abi::syscalls::SYSCALL_REMOVE_SMART_CONTRACT_BYTES => {
                access_class_for_builtin(Builtin::RemoveSmartContractBytes)
            }
            ivm_abi::syscalls::SYSCALL_REGISTER_SMART_CONTRACT_CODE => {
                access_class_for_builtin(Builtin::RegisterSmartContractCode)
            }
            ivm_abi::syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES => {
                access_class_for_builtin(Builtin::RegisterSmartContractBytes)
            }
            ivm_abi::syscalls::SYSCALL_ACTIVATE_CONTRACT_INSTANCE => {
                access_class_for_builtin(Builtin::ActivateContractInstance)
            }
            _ => IrAccessClass::Ledger(BuiltinAccess::Dynamic),
        },
        ir::Instr::ZkRootsGet { .. } => access_class_for_builtin(Builtin::ZkRootsGet),
        ir::Instr::ZkVoteGetTally { .. } => access_class_for_builtin(Builtin::ZkVoteGetTally),
        ir::Instr::VrfEpochSeed { .. } => access_class_for_builtin(Builtin::VrfEpochSeed),
        ir::Instr::SubscriptionBill => access_class_for_builtin(Builtin::SubscriptionBill),
        ir::Instr::SubscriptionRecordUsage => {
            access_class_for_builtin(Builtin::SubscriptionRecordUsage)
        }
        ir::Instr::StateGet { .. } => access_class_for_builtin(Builtin::StateGet),
        ir::Instr::StateSet { .. } => access_class_for_builtin(Builtin::StateSet),
        ir::Instr::StateDel { .. } => access_class_for_builtin(Builtin::StateDel),
        ir::Instr::StateScan { .. } => IrAccessClass::State(BuiltinAccess::StateRead),
        ir::Instr::StateHas { .. } => access_class_for_builtin(Builtin::StateHas),
        ir::Instr::StateLen { .. } => access_class_for_builtin(Builtin::StateLen),
        ir::Instr::StateCount { .. } => access_class_for_builtin(Builtin::StateCount),
        ir::Instr::BuildSubmitBallotInline { .. } => {
            access_class_for_builtin(Builtin::BuildSubmitBallotInline)
        }
        ir::Instr::VrfVerify { .. } => access_class_for_builtin(Builtin::VrfVerify),
        ir::Instr::VrfVerifyBatch { .. } => access_class_for_builtin(Builtin::VrfVerifyBatch),
        ir::Instr::AxtBegin { .. } => access_class_for_builtin(Builtin::AxtBegin),
        ir::Instr::AxtTouch { .. } => access_class_for_builtin(Builtin::AxtTouch),
        ir::Instr::StageAnchoredSpend { .. } => {
            access_class_for_builtin(Builtin::StageAnchoredSpend)
        }
        ir::Instr::VerifyDsProof { .. } => access_class_for_builtin(Builtin::VerifyDsProof),
        ir::Instr::AxtCommit => access_class_for_builtin(Builtin::AxtCommit),
        ir::Instr::SoracloudHostCall { .. } => {
            access_class_for_builtin(Builtin::SoracloudReadCommittedState)
        }
    }
}
fn detect_vector_usage(code: &[u8]) -> bool {
    const VECTOR_OPS: [u8; 14] = [
        instruction::wide::crypto::VADD32,
        instruction::wide::crypto::VADD64,
        instruction::wide::crypto::VAND,
        instruction::wide::crypto::VXOR,
        instruction::wide::crypto::VOR,
        instruction::wide::crypto::VROT32,
        instruction::wide::crypto::SHA256BLOCK,
        instruction::wide::crypto::AESENC,
        instruction::wide::crypto::AESDEC,
        instruction::wide::crypto::SETVL,
        instruction::wide::crypto::PARBEGIN,
        instruction::wide::crypto::PAREND,
        instruction::wide::memory::LOAD128,
        instruction::wide::memory::STORE128,
    ];
    code.chunks_exact(4).any(|chunk| {
        let word = u32::from_le_bytes(chunk.try_into().expect("word chunk"));
        let opcode = instruction::wide::opcode(word);
        VECTOR_OPS.contains(&opcode)
    })
}
fn detect_zk_usage(code: &[u8]) -> bool {
    const ZK_OPS: [u8; 7] = [
        instruction::wide::zk::ASSERT,
        instruction::wide::zk::ASSERT_EQ,
        instruction::wide::zk::FADD,
        instruction::wide::zk::FSUB,
        instruction::wide::zk::FMUL,
        instruction::wide::zk::FINV,
        instruction::wide::zk::ASSERT_RANGE,
    ];
    code.chunks_exact(4).any(|chunk| {
        let word = u32::from_le_bytes(chunk.try_into().expect("word chunk"));
        let opcode = instruction::wide::opcode(word);
        ZK_OPS.contains(&opcode)
    })
}
pub mod test_helpers {
    use super::*;
    /// Trigger just the CallMulti guard in codegen with a fabricated IR function.
    /// This avoids parsing/semantic stages and focuses on the emission error path.
    pub fn try_emit_callmulti_guard_only(ret_arity: usize) -> Result<(), String> {
        // Build a minimal IR function: one param, and a single CallMulti with `ret_arity` dests.
        let arg = ir::Temp(0);
        let mut dests = Vec::new();
        for i in 0..ret_arity {
            dests.push(ir::Temp(1 + i));
        }
        let bb = ir::BasicBlock {
            label: ir::Label(0),
            instrs: vec![
                ir::Instr::LoadVar {
                    dest: arg,
                    name: "a".to_string(),
                },
                ir::Instr::CallMulti {
                    callee: "g".to_string(),
                    args: vec![arg],
                    dests: dests.clone(),
                },
            ],
            terminator: ir::Terminator::Return(None),
        };
        let func = ir::Function {
            name: "f".to_string(),
            params: vec!["a".to_string()],
            blocks: vec![bb],
            entry: ir::Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        // Allocate registers once to mimic real emission environment
        let _alloc = regalloc::allocate(&func);
        // Visit instructions and hit the CallMulti guard path identical to emission.
        for bb in &func.blocks {
            for instr in &bb.instrs {
                if let ir::Instr::CallMulti { callee, dests, .. } = instr
                    && dests.len() > regalloc::MAX_RETURN_VALUES
                {
                    return Err(format!(
                        "too many return values in call to {}: {} > {}",
                        callee,
                        dests.len(),
                        regalloc::MAX_RETURN_VALUES
                    ));
                }
            }
        }
        Ok(())
    }
}
fn validate_codegen_supported(tp: &semantic::TypedProgram) -> Result<(), Vec<ir::LoweringFailure>> {
    use semantic::{ExprKind as EK, TypedItem, TypedStatement as S};
    fn expr_ok(e: &semantic::TypedExpr) -> Result<(), String> {
        match e.kind() {
            EK::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                expr_ok(cond)?;
                expr_ok(then_expr)?;
                expr_ok(else_expr)?;
                Ok(())
            }
            EK::If {
                condition,
                then_branch,
                else_branch,
            } => {
                expr_ok(condition)?;
                block_ok(then_branch)?;
                block_ok(else_branch)
            }
            EK::IfLet {
                value,
                then_branch,
                else_branch,
                ..
            } => {
                expr_ok(value)?;
                block_ok(then_branch)?;
                block_ok(else_branch)
            }
            EK::Match { value, arms } => {
                expr_ok(value)?;
                for arm in arms {
                    block_ok(&arm.body)?;
                }
                Ok(())
            }
            EK::OptionSome { value }
            | EK::ResultOk { value }
            | EK::ResultErr { error: value }
            | EK::Propagate { value } => expr_ok(value),
            EK::Binary { left, right, .. } => {
                expr_ok(left)?;
                expr_ok(right)
            }
            EK::Unary { expr, .. } => expr_ok(expr),
            EK::NumericCast { expr } => expr_ok(expr),
            EK::NumericTryCast { expr } => expr_ok(expr),
            EK::Call { args, .. } | EK::NamedCall { args, .. } => {
                for a in args {
                    expr_ok(a)?;
                }
                Ok(())
            }
            EK::Tuple(elems) | EK::List(elems) => {
                for t in elems {
                    expr_ok(t)?;
                }
                Ok(())
            }
            EK::JsonObject(entries) => {
                for (_, value) in entries {
                    expr_ok(value)?;
                }
                Ok(())
            }
            EK::JsonArray(elements) => {
                for element in elements {
                    expr_ok(element)?;
                }
                Ok(())
            }
            EK::ListComprehension {
                expression,
                source,
                condition,
                ..
            } => {
                expr_ok(source)?;
                expr_ok(expression)?;
                if let Some(condition) = condition {
                    expr_ok(condition)?;
                }
                Ok(())
            }
            EK::StructLiteral { fields, .. } => {
                for (_, value) in fields {
                    expr_ok(value)?;
                }
                Ok(())
            }
            EK::Member { object, .. } => expr_ok(object),
            EK::Index { target, index } => {
                expr_ok(target)?;
                expr_ok(index)
            }
            EK::VariantCode(_)
            | EK::IntLiteral(_)
            | EK::DecimalLiteral { .. }
            | EK::Bool(_)
            | EK::String(_)
            | EK::Bytes(_)
            | EK::Ident(_)
            | EK::OptionNone => Ok(()),
        }
    }
    fn block_ok(b: &semantic::TypedBlock) -> Result<(), String> {
        for s in &b.statements {
            match s.kind() {
                S::Let { value, .. } => expr_ok(value)?,
                S::Expr(e) => expr_ok(e)?,
                S::Return(Some(e)) => expr_ok(e)?,
                S::Return(None) | S::Break | S::Continue => {}
                S::If {
                    cond,
                    then_branch,
                    else_branch,
                } => {
                    expr_ok(cond)?;
                    block_ok(then_branch)?;
                    if let Some(b) = else_branch {
                        block_ok(b)?;
                    }
                }
                S::IfLet {
                    value,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    expr_ok(value)?;
                    block_ok(then_branch)?;
                    if let Some(block) = else_branch {
                        block_ok(block)?;
                    }
                }
                S::While { cond, body } => {
                    expr_ok(cond)?;
                    block_ok(body)?;
                }
                S::For {
                    init,
                    cond,
                    step,
                    body,
                    ..
                } => {
                    if let Some(i) = init {
                        // Walk the single init statement inline
                        match i.kind() {
                            S::Let { value, .. } => expr_ok(value)?,
                            S::Expr(e) => expr_ok(e)?,
                            other => {
                                return Err(format!(
                                    "unsupported init statement in for: {other:?}"
                                ));
                            }
                        }
                    }
                    if let Some(c) = cond {
                        expr_ok(c)?;
                    }
                    if let Some(st) = step {
                        match st.kind() {
                            S::Let { value, .. } => expr_ok(value)?,
                            S::Expr(e) => expr_ok(e)?,
                            other => {
                                return Err(format!(
                                    "unsupported step statement in for: {other:?}"
                                ));
                            }
                        }
                    }
                    block_ok(body)?;
                }
                S::ForEachMap { map, body, .. } => {
                    expr_ok(map)?;
                    block_ok(body)?;
                }
                S::MapSet { map, key, value } => {
                    expr_ok(map)?;
                    expr_ok(key)?;
                    expr_ok(value)?;
                }
            }
        }
        if let Some(tail) = &b.tail {
            expr_ok(tail)?;
        }
        Ok(())
    }
    let mut failures = Vec::new();
    for item in &tp.items {
        let TypedItem::Function(f) = item;
        if let Err(message) = block_ok(&f.body) {
            failures.push(ir::LoweringFailure {
                message,
                location: f.location,
            });
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}
