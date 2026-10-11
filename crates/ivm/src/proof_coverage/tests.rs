//! Source-checked completeness tests for the proof-coverage inventory.
//!
//! Each test compares one inventory table with its source owner in both
//! directions. The proof-code checks are token drift guards over reviewed
//! claims; they are not behavioural proof-coverage verification.

use std::collections::{BTreeMap, BTreeSet};

use super::traps::VM_ERROR_COUNT;
use super::{source_scan as scan, *};
use crate::{
    ExecutionDeferral, HostOutputResource, IVM, Perm, SyscallPolicy, VMError, VmTrapKind,
    host::host_syscall_metering_spec,
    instruction::wide,
    numeric::{NumericFaultV1, PointerAbiFaultV1},
    syscall_metering::SyscallMetering,
    syscalls,
};

const ABI_INSTRUCTION: &str = "crates/ivm_abi/src/instruction.rs";
const ABI_SYSCALLS: &str = "crates/ivm_abi/src/syscalls.rs";
const ABI_ERROR: &str = "crates/ivm_abi/src/error.rs";
const ABI_NUMERIC: &str = "crates/iroha_data_model/src/executor/fault.rs";
const INTERPRETER: &str = "crates/ivm/src/ivm.rs";
const CALL_RUNTIME: &str = "crates/ivm/src/call_runtime.rs";
const PROOF_ROOT: &str = "crates/iroha_core_privacy/src/execution_proofs/ivm_step_air.rs";
const PROOF_MODULE: &str = "crates/iroha_core_privacy/src/execution_proofs/mod.rs";
const PROOF_REGISTRY: &str = "crates/iroha_core_privacy/src/execution_proofs/registry.rs";
const CORE_HOST: &str = "crates/iroha_core/src/smartcontracts/ivm/host.rs";

fn names<'a>(values: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    values.into_iter().map(str::to_owned).collect()
}

/// Turn a failed comparison into the error a completeness check reports.
fn ensure(holds: bool, message: impl FnOnce() -> String) -> Result<(), String> {
    if holds { Ok(()) } else { Err(message()) }
}

/// Require a completeness check to hold against the real source.
#[track_caller]
fn passes(result: Result<(), String>) {
    if let Err(message) = result {
        panic!("{message}");
    }
}

/// Require a completeness check to reject a mutated source and name `needle`.
#[track_caller]
fn rejects(result: Result<(), String>, needle: &str) {
    match result {
        Ok(()) => panic!("a mutated source passed the completeness check for `{needle}`"),
        Err(message) => assert!(
            message.contains(needle),
            "rejection `{message}` does not name `{needle}`"
        ),
    }
}

/// Insert `addition` directly after the first occurrence of `anchor`.
#[track_caller]
fn insert_after(text: &str, anchor: &str, addition: &str) -> String {
    let at = text
        .find(anchor)
        .unwrap_or_else(|| panic!("mutation anchor `{anchor}` not found"))
        + anchor.len();
    format!("{}{addition}{}", &text[..at], &text[at..])
}

/// Remove the first occurrence of `removed`.
#[track_caller]
fn remove_once(text: &str, removed: &str) -> String {
    assert!(
        text.contains(removed),
        "mutation target `{removed}` not found"
    );
    text.replacen(removed, "", 1)
}

/// One value of every `VMError` variant, in declaration order.
fn vm_error_samples() -> Vec<VMError> {
    let budget = iroha_allocation::AllocationBudget::new(1);
    let occupied = budget
        .try_reserve_bytes(1)
        .expect("reserve the whole budget");
    let refusal = budget
        .try_reserve_bytes(1)
        .expect_err("an exhausted budget refuses");
    drop(occupied);
    vec![
        VMError::ExecutionDeferred(ExecutionDeferral::AllocationUnavailable),
        VMError::AllocationDeferred(refusal),
        VMError::Metered {
            gas: 1,
            source: Box::new(VMError::OutOfGas),
        },
        VMError::OutOfGas,
        VMError::OutOfMemory,
        VMError::MemoryAccessViolation {
            addr: 0,
            perm: Perm::READ,
        },
        VMError::MisalignedAccess { addr: 1 },
        VMError::MemoryOutOfBounds,
        VMError::DecodeError,
        VMError::InvalidOpcode(0),
        VMError::UnknownSyscall(0),
        VMError::HostUnavailable,
        VMError::NotImplemented { syscall: 0 },
        VMError::SyscallGasQuoteExceeded {
            quoted: 1,
            actual: 2,
        },
        VMError::SyscallMeteringModeMismatch { syscall: 0 },
        VMError::GasCostOverflow,
        VMError::SyscallOutOfGas {
            syscall: 0,
            phase: 0,
        },
        VMError::NumericFault(NumericFaultV1::DivisionByZero),
        VMError::PointerAbiFault(PointerAbiFaultV1::WrongType),
        VMError::AssertionFailed,
        VMError::ContractAbort {
            contract: "c".into(),
            name: "n".into(),
            error_type: "e".into(),
            schema_hash: [0; 32],
            code: 1,
            message: None,
        },
        VMError::ExceededMaxCycles,
        VMError::InvalidMetadata,
        VMError::UnsupportedProgramVersion { major: 9, minor: 9 },
        VMError::UnsupportedProgramFeatureBits { bits: 0x80 },
        VMError::UnsupportedProgramAbiVersion { version: 9 },
        VMError::ProgramVectorLengthTooLarge {
            vector_length: 255,
            max_allowed: 1,
        },
        VMError::ArtifactAbiHashMismatch {
            expected: [0; 32],
            actual: [1; 32],
        },
        VMError::GenericSyscallNotAllowed { syscall: 0 },
        VMError::InvalidVectorLength { vector_length: 0 },
        VMError::MissingHalt,
        VMError::VectorExtensionDisabled,
        VMError::ZkExtensionDisabled,
        VMError::NullifierAlreadyUsed,
        VMError::PermissionDenied,
        VMError::ReentrantCall,
        VMError::CallDepthExceeded,
        VMError::PrivacyViolation,
        VMError::RegisterOutOfBounds,
        VMError::NoritoInvalid,
        VMError::AbiTypeNotAllowed { abi: 1, type_id: 0 },
        VMError::HostOutputBudgetExceeded {
            resource: HostOutputResource::Items,
            attempted: 2,
            limit: 1,
        },
        VMError::AmxBudgetExceeded {
            dataspace: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            stage: iroha_data_model::errors::AmxStage::Commit,
            elapsed_ms: 2,
            budget_ms: 1,
        },
    ]
}

#[test]
fn opcode_inventory_names_exactly_the_ninety_admitted_opcodes() {
    let admitted: Vec<u8> = (0..=u8::MAX)
        .filter(|opcode| wide::is_valid_opcode(*opcode))
        .collect();
    assert_eq!(admitted.len(), 90, "the admitted opcode count changed");
    assert_eq!(OPCODE_COUNT, 90);
    assert_eq!(
        OPCODES.iter().map(|entry| entry.opcode).collect::<Vec<_>>(),
        admitted,
        "inventory and admission gate must list the same opcodes in order"
    );
    for opcode in 0..=u8::MAX {
        assert_eq!(
            opcode_entry(opcode).is_some(),
            wide::is_valid_opcode(opcode),
            "opcode 0x{opcode:02x} admission/inventory mismatch"
        );
        assert_eq!(
            opcode_entry(opcode).map(|entry| entry.opcode),
            wide::is_valid_opcode(opcode).then_some(opcode)
        );
    }
    assert_eq!(summary().opcodes, 90);
}

/// Compare the opcode constants declared by `source` with the inventory.
fn check_opcode_constants(source: &str) -> Result<(), String> {
    let constants = scan::opcode_constants(source);
    let admitted: BTreeSet<(String, String, u8)> = constants
        .iter()
        .filter(|(module, _, _)| scan::OPCODE_MODULES.contains(&module.as_str()))
        .cloned()
        .collect();
    let inventory: BTreeSet<(String, String, u8)> = OPCODES
        .iter()
        .map(|entry| (entry.module.to_owned(), entry.name.to_owned(), entry.opcode))
        .collect();
    ensure(inventory.len() == OPCODES.len(), || {
        "opcode names are not unique".to_owned()
    })?;
    ensure(admitted.len() == OPCODE_COUNT, || {
        format!(
            "{} admitted opcode constants are declared, the inventory counts {OPCODE_COUNT}",
            admitted.len()
        )
    })?;
    ensure(admitted == inventory, || {
        format!(
            "opcode constants and the inventory differ: {:?}",
            admitted
                .symmetric_difference(&inventory)
                .collect::<Vec<_>>()
        )
    })?;
    let reserved_source: BTreeSet<(String, u8)> = constants
        .iter()
        .filter(|(module, _, _)| module == "iso20022")
        .map(|(_, name, value)| (name.clone(), *value))
        .collect();
    let reserved: BTreeSet<(String, u8)> = RESERVED_OPCODES
        .iter()
        .map(|entry| (entry.name.to_owned(), entry.opcode))
        .collect();
    ensure(reserved_source == reserved, || {
        "reserved ISO 20022 opcodes differ".to_owned()
    })?;
    ensure(
        constants.len() == OPCODES.len() + RESERVED_OPCODES.len(),
        || "an opcode constant lives outside the admitted and reserved modules".to_owned(),
    )
}

#[test]
fn opcode_names_and_values_match_the_abi_constant_source() {
    passes(check_opcode_constants(&scan::read(ABI_INSTRUCTION)));
    for entry in RESERVED_OPCODES {
        assert!(!wide::is_valid_opcode(entry.opcode));
        assert!(opcode_entry(entry.opcode).is_none());
    }
}

/// Every function or method name the terminal block of `run_with_host_ref`
/// calls. A result returned without `?` needs no trap token and no
/// propagated helper, so the whole call surface is pinned: a new call there
/// requires a review of the `terminal` phase.
const TERMINAL_CALLS: [&str; 32] = [
    "abort_host_register_log_isolation",
    "and_then",
    "as_deref_mut",
    "as_ref",
    "call_result_word_count",
    "capture_trap_at",
    "checked_sub",
    "clear",
    "clone",
    "commit_memory_after_run_if_needed",
    "complete",
    "diagnostic_step_state",
    "ensure_healthy",
    "err",
    "expect",
    "finish_run",
    "finish_step",
    "finish_trace_invocation",
    "is_ok",
    "last",
    "map",
    "map_err",
    "map_or",
    "native_padding_completed",
    "prepare_trace_padding",
    "publish_trace_cycles",
    "records",
    "reserve",
    "resume_unwind",
    "saturating_sub",
    "take",
    "unwrap_or",
];

/// Every non-`VMError` argument the terminal block gives to `Err(`: the
/// stored contract abort, the caught panic payload and the final result
/// binding.
const TERMINAL_ERR_ARGUMENTS: [&str; 3] = ["err", "error", "payload"];

/// Compare one source region with its inventoried run phase.
fn check_run_phase(id: &str, surface: &scan::RegionSurface) -> Result<(), String> {
    let phase = run_phase(id).ok_or_else(|| format!("run phase `{id}` is not inventoried"))?;
    ensure(
        surface.direct_traps == names(phase.direct_traps.iter().copied()),
        || {
            format!(
                "direct traps of run phase `{id}` changed: {:?}",
                surface.direct_traps
            )
        },
    )?;
    ensure(
        surface.fallible_helpers == names(phase.fallible_helpers.iter().copied()),
        || {
            format!(
                "fallible helpers of run phase `{id}` changed: {:?}",
                surface.fallible_helpers
            )
        },
    )?;
    for source in phase.result_sources {
        ensure(surface.code.contains(source), || {
            format!("result source `{source}` of run phase `{id}` is gone")
        })?;
    }
    Ok(())
}

/// Compare `IVM::run_with_host_ref` in `source` with the inventoried run
/// phases and the fault and privacy-tag surface of every opcode.
fn check_interpreter_dispatch(source: &str) -> Result<(), String> {
    let dispatch = scan::interpreter_dispatch(source, PRIVACY_HELPERS);
    check_run_phase("invocation_entry", &dispatch.entry)?;
    check_run_phase("step_preamble", &dispatch.preamble)?;
    check_run_phase("terminal", &dispatch.terminal)?;
    ensure(dispatch.terminal.calls == names(TERMINAL_CALLS), || {
        format!(
            "calls of run phase `terminal` changed: {:?}; review its result sources",
            dispatch
                .terminal
                .calls
                .symmetric_difference(&names(TERMINAL_CALLS))
                .collect::<Vec<_>>()
        )
    })?;
    ensure(
        dispatch.terminal.err_arguments == names(TERMINAL_ERR_ARGUMENTS),
        || {
            format!(
                "returned errors of run phase `terminal` changed: {:?}; review its result sources",
                dispatch.terminal.err_arguments
            )
        },
    )?;
    let mut seen = BTreeMap::new();
    for arm in &dispatch.arms {
        for name in &arm.names {
            ensure(seen.insert(name.clone(), arm).is_none(), || {
                format!("opcode {name} has two interpreter arms")
            })?;
        }
    }
    let dispatched: BTreeSet<String> = seen.keys().cloned().collect();
    let inventory = names(OPCODES.iter().map(|entry| entry.name));
    ensure(dispatched == inventory, || {
        format!(
            "interpreter arms and the inventory name different opcodes: {:?}",
            dispatched
                .symmetric_difference(&inventory)
                .collect::<Vec<_>>()
        )
    })?;
    for entry in OPCODES.iter() {
        let arm = seen[entry.name];
        ensure(
            arm.direct_traps == names(entry.direct_traps.iter().copied()),
            || {
                format!(
                    "direct traps of {} changed: {:?}",
                    entry.name, arm.direct_traps
                )
            },
        )?;
        ensure(
            arm.fallible_helpers == names(entry.fallible_helpers.iter().copied()),
            || {
                format!(
                    "fallible helpers of {} changed: {:?}",
                    entry.name, arm.fallible_helpers
                )
            },
        )?;
        ensure(
            arm.tag_surface == names(entry.tag_surface.iter().copied()),
            || {
                format!(
                    "privacy-tag surface of {} changed: {:?}; review its private-masking obligation",
                    entry.name, arm.tag_surface
                )
            },
        )?;
    }
    let default_arms: Vec<_> = dispatch
        .arms
        .iter()
        .filter(|arm| arm.names.is_empty())
        .collect();
    ensure(
        default_arms.len() == 1 && default_arms[0].direct_traps == names(["InvalidOpcode"]),
        || "the default dispatch arm must be the single InvalidOpcode trap".to_owned(),
    )?;
    // The privacy helpers are exactly the interpreter functions that touch a
    // privacy tag and are called by a dispatch arm, so an arm cannot reach
    // the tag surface through a helper the inventory does not name.
    let code = scan::strip_line_comments(source);
    let touching = scan::privacy_functions(&code);
    let called: BTreeSet<String> = dispatch
        .arms
        .iter()
        .flat_map(|arm| arm.calls.iter().cloned())
        .filter(|name| touching.contains(name))
        .collect();
    ensure(called == names(PRIVACY_HELPERS.iter().copied()), || {
        format!(
            "privacy helpers called by interpreter arms changed: {:?}",
            called
                .symmetric_difference(&names(PRIVACY_HELPERS.iter().copied()))
                .collect::<Vec<_>>()
        )
    })?;
    // Syscall dispatch enforces the same surface for the selected syscall's
    // registers in both metering modes.
    for function in SYSCALL_PRIVACY_FUNCTIONS {
        ensure(touching.contains(*function), || {
            format!("syscall privacy function {function} no longer touches a privacy tag")
        })?;
    }
    for mode in ["execute_reserved_syscall", "execute_staged_syscall"] {
        let calls = scan::called_names(&scan::function_body(&code, mode));
        for function in SYSCALL_PRIVACY_FUNCTIONS {
            ensure(calls.contains(*function), || {
                format!("{mode} no longer calls {function}")
            })?;
        }
    }
    let dispatcher = scan::called_names(&scan::function_body(
        &code,
        "execute_syscall_with_register_log",
    ));
    ensure(
        dispatcher.contains("execute_reserved_syscall")
            && dispatcher.contains("execute_staged_syscall"),
        || "syscall dispatch no longer selects the reserved or staged executor".to_owned(),
    )
}

/// Compare `IVM::begin_root_call` in `source` with its inventoried run phase.
fn check_root_call_initialization(source: &str) -> Result<(), String> {
    let code = scan::strip_line_comments(source);
    let surface = scan::region_surface(&scan::function_body(&code, "begin_root_call"));
    check_run_phase("root_call_initialization", &surface)
}

#[test]
fn opcode_fault_surface_matches_the_interpreter_dispatch() {
    passes(check_interpreter_dispatch(&scan::read_non_test(
        INTERPRETER,
    )));
}

#[test]
fn run_phases_match_the_interpreter_and_root_call_sources() {
    passes(check_root_call_initialization(&scan::read_non_test(
        CALL_RUNTIME,
    )));
    let ids: Vec<_> = RUN_PHASES.iter().map(|phase| phase.id).collect();
    assert_eq!(
        ids,
        [
            "invocation_entry",
            "root_call_initialization",
            "step_preamble",
            "terminal"
        ]
    );
    let variants = names(VM_ERRORS.iter().map(|entry| entry.variant));
    for phase in RUN_PHASES {
        assert_eq!(run_phase(phase.id), Some(phase));
        assert!(!phase.summary.is_empty(), "{}", phase.id);
        assert!(!phase.obligations.is_empty(), "{}", phase.id);
        let unique: BTreeSet<_> = phase.obligations.iter().collect();
        assert_eq!(unique.len(), phase.obligations.len(), "{}", phase.id);
        for trap in phase.direct_traps {
            assert!(
                variants.contains(*trap),
                "{}: unknown trap {trap}",
                phase.id
            );
        }
        let code = scan::read_code(phase.path);
        assert!(
            code.contains(&format!("fn {}(", phase.function)),
            "{}: {} no longer defines {}",
            phase.id,
            phase.path,
            phase.function
        );
    }
    assert!(run_phase("missing").is_none());
    // The interpreter enters root-call initialization from the entry phase,
    // and a failure there carries the initialization origin's obligations.
    let entry = run_phase("invocation_entry").expect("entry phase");
    assert!(entry.fallible_helpers.contains(&"begin_root_call"));
    let root = run_phase("root_call_initialization").expect("root phase");
    for obligation in TrapOrigin::InitializationTrap.obligations() {
        assert!(root.obligations.contains(obligation), "{obligation:?}");
    }
    let terminal = run_phase("terminal").expect("terminal phase");
    assert!(terminal.obligations.contains(&Obligation::Padding));
    assert_eq!(
        terminal.result_sources,
        ["contract_abort_error", "ensure_healthy"]
    );
    // Every variant root-call initialization names has that origin recorded.
    for trap in root.direct_traps {
        let entry = VM_ERRORS
            .iter()
            .find(|entry| entry.variant == *trap)
            .expect("inventoried variant");
        assert!(
            entry.producers().iter().any(|producer| {
                producer.origin == TrapOrigin::InitializationTrap && producer.path == root.path
            }),
            "{trap} lacks the initialization origin in {}",
            root.path
        );
    }
}

#[test]
fn opcode_traps_and_obligation_profiles_are_consistent() {
    let variants = names(VM_ERRORS.iter().map(|entry| entry.variant));
    let tag_tokens: BTreeSet<&str> = TAG_ACCESSORS
        .iter()
        .chain(PRIVACY_HELPERS)
        .copied()
        .collect();
    assert_eq!(
        tag_tokens.len(),
        TAG_ACCESSORS.len() + PRIVACY_HELPERS.len(),
        "tag accessors and privacy helpers are distinct names"
    );
    assert_eq!(
        scan::TAG_ACCESSORS
            .iter()
            .map(|(name, _)| *name)
            .collect::<BTreeSet<_>>(),
        TAG_ACCESSORS.iter().copied().collect(),
        "the scanner and the inventory name the same tag accessors"
    );
    for entry in OPCODES.iter() {
        let has = |obligation| entry.obligations.contains(&obligation);
        let traps = |variant| entry.direct_traps.contains(&variant);
        for trap in entry.direct_traps {
            assert!(
                variants.contains(*trap),
                "{}: unknown trap {trap}",
                entry.name
            );
        }
        let unique: BTreeSet<_> = entry.obligations.iter().collect();
        assert_eq!(unique.len(), entry.obligations.len(), "{}", entry.name);
        for required in [Obligation::Fetch, Obligation::Gas, Obligation::Faults] {
            assert!(has(required), "{} lacks {required:?}", entry.name);
        }
        // One rule for private masking: the class is present exactly when one
        // step reads or writes a privacy tag. That is the case when the arm
        // touches the tag surface or raises the privacy trap itself, or when
        // it dispatches a syscall, whose handler enforces the same surface.
        assert!(
            entry.tag_surface.is_sorted()
                && entry
                    .tag_surface
                    .iter()
                    .all(|token| tag_tokens.contains(token)),
            "{}: tag surface holds sorted accessor and helper names",
            entry.name
        );
        assert_eq!(
            entry.engages_privacy_tags(),
            !entry.tag_surface.is_empty()
                || traps("PrivacyViolation")
                || entry.effect == StepEffect::HostCall,
            "{}",
            entry.name
        );
        assert_eq!(
            has(Obligation::PrivateMasking),
            entry.engages_privacy_tags(),
            "{}: private masking must follow the privacy-tag surface",
            entry.name
        );
        if traps("PrivacyViolation") {
            assert!(
                entry.tag_surface.contains(&"tag")
                    || entry
                        .tag_surface
                        .iter()
                        .any(|token| PRIVACY_HELPERS.contains(token)),
                "{}: a privacy trap follows a tag read or a privacy helper",
                entry.name
            );
        }
        for helper in entry.fallible_helpers {
            assert_eq!(
                PRIVACY_HELPERS.contains(helper),
                entry.tag_surface.contains(helper),
                "{}: fallible privacy helper {helper} belongs to the tag surface",
                entry.name
            );
        }
        assert_eq!(
            has(Obligation::Vector),
            traps("VectorExtensionDisabled"),
            "{}: vector obligation must follow the vector-extension gate",
            entry.name
        );
        assert_eq!(
            entry.effect == StepEffect::ZkFieldOrAssertion,
            traps("ZkExtensionDisabled"),
            "{}: ZK effect must follow the ZK-extension gate",
            entry.name
        );
        assert_eq!(
            has(Obligation::Precompile),
            entry.effect == StepEffect::CryptographicPrimitive,
            "{}",
            entry.name
        );
        assert_eq!(
            has(Obligation::Parallel),
            entry.effect == StepEffect::ParallelMarker,
            "{}",
            entry.name
        );
        assert_eq!(
            has(Obligation::HostResult),
            entry.effect == StepEffect::HostCall,
            "{}",
            entry.name
        );
        assert_eq!(
            has(Obligation::Calls),
            matches!(
                entry.pc,
                PcTransition::DirectRelative16WithOptionalLink
                    | PcTransition::DirectRelative24AndLink
                    | PcTransition::IndirectMaskedOrProtectedReturn
            ),
            "{}",
            entry.name
        );
        assert_eq!(
            has(Obligation::Calls),
            has(Obligation::VmRecursion),
            "{}: protected calls and returns carry the callable-depth obligation",
            entry.name
        );
        assert_eq!(
            entry.pc != PcTransition::Sequential,
            entry.effect == StepEffect::Control,
            "{}: only control opcodes leave the sequential PC edge",
            entry.name
        );
    }
    // Only opcodes that touch no register, vector register or guest memory
    // stay outside private masking.
    let unmasked: BTreeSet<_> = OPCODES
        .iter()
        .filter(|entry| !entry.obligations.contains(&Obligation::PrivateMasking))
        .map(|entry| entry.name)
        .collect();
    assert_eq!(
        unmasked,
        BTreeSet::from(["HALT", "JMP", "PARBEGIN", "PAREND", "SETVL"])
    );
    let call_helpers: BTreeSet<_> = OPCODES
        .iter()
        .filter(|entry| {
            entry
                .fallible_helpers
                .iter()
                .any(|helper| matches!(*helper, "begin_child_call" | "finish_call"))
        })
        .map(|entry| entry.name)
        .collect();
    assert_eq!(call_helpers, BTreeSet::from(["JAL", "JALR", "JALS"]));
    assert_eq!(
        opcode_entry(wide::control::JR).map(|entry| entry.pc),
        Some(PcTransition::IndirectRegisterOrStrictTrap)
    );
    assert_eq!(
        opcode_entry(wide::control::HALT).map(|entry| entry.pc),
        Some(PcTransition::HaltOrStrictReturnTrap)
    );
    for strict in [wide::control::JR, wide::control::HALT] {
        assert!(
            opcode_entry(strict)
                .is_some_and(|entry| entry.direct_traps.contains(&"AssertionFailed")),
            "forbidden protected forms trap"
        );
    }
}

#[test]
fn syscall_inventory_matches_the_abi_list_and_canonical_names() {
    let abi = syscalls::abi_syscall_list();
    assert_eq!(
        SYSCALLS
            .iter()
            .map(|entry| entry.number)
            .collect::<Vec<_>>(),
        abi,
        "inventory and abi_syscall_list() must name the same syscalls in order"
    );
    assert_eq!(SYSCALL_COUNT, abi.len());
    for number in abi {
        let entry = syscall_entry(*number)
            .unwrap_or_else(|| panic!("syscall 0x{number:X} is not inventoried"));
        assert_eq!(
            Some(entry.name),
            syscalls::syscall_name(*number),
            "syscall 0x{number:X} name differs from ABI_V1_SYSCALL_METADATA"
        );
    }
    for entry in SYSCALLS.iter() {
        assert!(
            syscalls::is_syscall_allowed(SyscallPolicy::AbiV1, entry.number),
            "{} is inventoried but not in the ABI",
            entry.name
        );
        assert!(syscalls::syscall_name(entry.number).is_some());
    }
    assert!(syscall_entry(u32::MAX).is_none());
    let unique: BTreeSet<_> = SYSCALLS.iter().map(|entry| entry.name).collect();
    assert_eq!(unique.len(), SYSCALLS.len(), "syscall names are unique");
}

/// Compare the `SYSCALL_*` constants declared by `source` with the inventory
/// and the host-private list.
fn check_syscall_constants(source: &str) -> Result<(), String> {
    let declared: BTreeSet<(String, u32)> = scan::syscall_constants(source).into_iter().collect();
    let mut inventory: BTreeSet<(String, u32)> = SYSCALLS
        .iter()
        .map(|entry| (entry.name.to_owned(), entry.number))
        .collect();
    for entry in HOST_PRIVATE_SYSCALLS {
        ensure(
            inventory.insert((entry.name.to_owned(), entry.number)),
            || format!("{} is both inventoried and host-private", entry.name),
        )?;
    }
    ensure(declared == inventory, || {
        format!(
            "SYSCALL_* constants are neither inventoried nor host-private: {:?}",
            declared
                .symmetric_difference(&inventory)
                .collect::<Vec<_>>()
        )
    })
}

#[test]
fn syscall_constants_are_inventoried_or_host_private() {
    passes(check_syscall_constants(&scan::read(ABI_SYSCALLS)));
    for entry in HOST_PRIVATE_SYSCALLS {
        assert!(
            syscalls::is_koto_test_syscall(entry.number),
            "{}",
            entry.name
        );
        assert!(!syscalls::is_syscall_allowed(
            SyscallPolicy::AbiV1,
            entry.number
        ));
        assert!(syscall_entry(entry.number).is_none());
        assert!(syscalls::syscall_name(entry.number).is_none());
    }
}

#[test]
fn syscall_relations_agree_with_the_access_and_metering_registries() {
    let mut used = BTreeSet::new();
    for entry in SYSCALLS.iter() {
        used.insert(entry.relation);
        let access = syscalls::registered_syscall_access(entry.number)
            .unwrap_or_else(|| panic!("{} has no registered access class", entry.name));
        assert!(
            entry.relation.expected_access().contains(&access),
            "{}: relation {:?} does not admit access {access:?}",
            entry.name,
            entry.relation
        );
        let spec = host_syscall_metering_spec(SyscallPolicy::AbiV1, entry.number)
            .unwrap_or_else(|| panic!("{} has no registered metering spec", entry.name));
        assert_eq!(
            entry.relation == SyscallRelation::Numeric,
            syscalls::is_numeric_v1_syscall(entry.number),
            "{}",
            entry.name
        );
        assert_eq!(
            entry.relation == SyscallRelation::Numeric,
            spec.metering == SyscallMetering::Staged,
            "{}: only numeric syscalls use staged metering",
            entry.name
        );
        assert_eq!(
            entry.relation == SyscallRelation::Axt,
            syscalls::is_axt_syscall(entry.number),
            "{}",
            entry.name
        );
        if syscalls::is_json_getter_syscall(entry.number) {
            assert_eq!(
                entry.relation,
                SyscallRelation::TypedCodec,
                "{}",
                entry.name
            );
        }
        if syscalls::GENERIC_PROGRAM_DENIED_SYSCALLS_V1.contains(&entry.number) {
            assert!(
                !matches!(
                    entry.relation,
                    SyscallRelation::Numeric
                        | SyscallRelation::TypedCodec
                        | SyscallRelation::HashPrecompile
                ),
                "{}: contract-bound syscalls are never pure codec work",
                entry.name
            );
        }
        let obligations = entry.relation.obligations();
        for required in [Obligation::Gas, Obligation::Faults, Obligation::HostResult] {
            assert!(obligations.contains(&required), "{}", entry.name);
        }
        let reads = matches!(
            access,
            syscalls::SyscallAccess::StateRead | syscalls::SyscallAccess::LedgerRead
        );
        if reads {
            assert!(
                obligations.contains(&Obligation::StateRead),
                "{}",
                entry.name
            );
        }
        let writes = matches!(
            access,
            syscalls::SyscallAccess::StateWrite
                | syscalls::SyscallAccess::LedgerWrite
                | syscalls::SyscallAccess::Dynamic
        );
        if writes {
            assert!(
                obligations.contains(&Obligation::StateEffect),
                "{}",
                entry.name
            );
        }
    }
    assert_eq!(
        used,
        SyscallRelation::ALL.into_iter().collect(),
        "every relation class is used by at least one syscall"
    );
    let ids: BTreeSet<_> = SyscallRelation::ALL
        .iter()
        .map(|relation| relation.id())
        .collect();
    assert_eq!(ids.len(), SyscallRelation::COUNT);
    for relation in SyscallRelation::ALL {
        let unique: BTreeSet<_> = relation.obligations().iter().collect();
        assert_eq!(unique.len(), relation.obligations().len(), "{relation:?}");
    }
    let relation = |number| syscall_entry(number).map(|entry| entry.relation);
    assert_eq!(
        relation(syscalls::SYSCALL_VRF_EPOCH_SEED),
        Some(SyscallRelation::VrfEpochSeed)
    );
    assert_eq!(
        relation(syscalls::SYSCALL_CALL_CONTRACT),
        Some(SyscallRelation::NestedInvocation)
    );
    for number in [
        syscalls::SYSCALL_VERIFY_PROOF,
        syscalls::SYSCALL_ZK_VERIFY_BATCH,
        syscalls::SYSCALL_ZK_VOTE_VERIFY_BALLOT,
        syscalls::SYSCALL_ZK_VOTE_VERIFY_TALLY,
    ] {
        assert_eq!(
            relation(number),
            Some(SyscallRelation::GuestProofVerification)
        );
    }
    assert!(
        SyscallRelation::Axt
            .obligations()
            .contains(&Obligation::GuestProofVerification),
        "VERIFY_DS_PROOF keeps its AXT-specific proof check"
    );
    assert!(
        SyscallRelation::NestedInvocation
            .obligations()
            .contains(&Obligation::VmRecursion)
    );
}

#[test]
fn typed_nested_invocation_requires_initialized_ordered_argument_and_return_tables() {
    let entry = syscall_entry(syscalls::SYSCALL_CALL_CONTRACT).expect("A9 is inventoried");
    assert_eq!(entry.relation, SyscallRelation::NestedInvocation);
    for obligation in [
        Obligation::TypedValues,
        Obligation::Initialization,
        Obligation::MemoryOrdering,
        Obligation::Pointers,
        Obligation::Calls,
        Obligation::Copyback,
        Obligation::VmRecursion,
        Obligation::ProofComposition,
        Obligation::Gas,
        Obligation::Faults,
        Obligation::HostResult,
        Obligation::StateRead,
        Obligation::StateEffect,
        Obligation::StatementBinding,
    ] {
        assert!(
            entry.relation.obligations().contains(&obligation),
            "typed A9 omits {obligation:?}"
        );
    }
}

#[test]
fn syscall_binding_status_combines_result_trap_and_statement() {
    use CoverageStatus::{Complete, ComponentOnly, Uncovered};
    let entry = |result, trap, statement| SyscallEntry {
        number: 0,
        name: "SAMPLE",
        relation: SyscallRelation::Diagnostic,
        result,
        trap,
        statement,
    };
    assert_eq!(entry(Uncovered, Uncovered, Uncovered).status(), Uncovered);
    assert_eq!(entry(Complete, Complete, Complete).status(), Complete);
    for partial in [
        entry(Complete, Uncovered, Uncovered),
        entry(Complete, Complete, Uncovered),
        entry(ComponentOnly, ComponentOnly, ComponentOnly),
        entry(Complete, Complete, ComponentOnly),
    ] {
        assert_eq!(partial.status(), ComponentOnly);
    }
    for entry in SYSCALLS.iter() {
        assert_eq!(
            (entry.result, entry.trap, entry.statement),
            (Uncovered, Uncovered, Uncovered),
            "{}: no syscall relation exists in the proof code",
            entry.name
        );
    }
}

#[test]
fn default_syscall_exclusions_are_empty_and_completion_stays_open() {
    assert!(DEFAULT_SYSCALL_EXCLUSIONS.is_empty());
    assert!(COMPLETE_RELATION.is_none());
    assert!(completion_open());
    let counts = summary();
    assert_eq!(counts.syscalls, syscalls::abi_syscall_list().len());
    assert_eq!(counts.syscalls_complete, 0);
    assert_eq!(counts.opcodes_complete, 0);
    assert_eq!(counts.trap_kinds_complete, 0);
    assert_eq!(counts.numeric_faults_complete, 0);
    assert_eq!(counts.pointer_abi_faults_complete, 0);
    assert_eq!(FAULT_CODE_COVERAGE, CoverageStatus::Uncovered);
    assert_eq!(counts.open_semantics, OPEN_SEMANTICS.len());
    assert!(!OPEN_SEMANTICS.is_empty());
    // Today every blocker except the exclusion list is raised, each on its
    // own evidence.
    let current = CompletionInputs::current();
    assert_eq!(current.relation, COMPLETE_RELATION);
    assert_eq!(current.syscall_exclusions, DEFAULT_SYSCALL_EXCLUSIONS);
    assert_eq!(current.open_semantics, OPEN_SEMANTICS);
    assert_eq!(current.summary, counts);
    assert_eq!(current.invocation_obligations, INVOCATION_OBLIGATIONS);
    assert_eq!(
        completion_blockers(&current),
        [
            CompletionBlocker::NoRegisteredRelation,
            CompletionBlocker::OpenSemantics,
            CompletionBlocker::OpcodesIncomplete,
            CompletionBlocker::SyscallsIncomplete,
            CompletionBlocker::TrapKindsIncomplete,
            CompletionBlocker::FaultCodesIncomplete,
            CompletionBlocker::InvocationObligationsIncomplete,
        ]
    );
}

/// Inputs under which every completion condition holds: a registered
/// relation, no exclusion, no open semantic and every entry complete.
fn closed_inputs(obligations: &[InvocationObligation]) -> CompletionInputs<'_> {
    let counts = summary();
    CompletionInputs {
        relation: Some("native_proved_invocation"),
        syscall_exclusions: &[],
        open_semantics: &[],
        summary: InventorySummary {
            opcodes_uncovered: 0,
            opcodes_component_only: 0,
            opcodes_complete: counts.opcodes,
            syscalls_complete: counts.syscalls,
            trap_kinds_complete: counts.trap_kinds,
            numeric_faults_complete: counts.numeric_faults,
            pointer_abi_faults_complete: counts.pointer_abi_faults,
            open_semantics: 0,
            ..counts
        },
        invocation_obligations: obligations,
    }
}

/// The completion decision must stay open for each condition on its own:
/// a registered relation with every entry complete is still open while one
/// semantic is unmapped, one syscall is excluded or one entry is incomplete.
#[test]
fn completion_decision_isolates_every_blocker() {
    use CompletionBlocker as Blocker;
    let complete: Vec<InvocationObligation> = INVOCATION_OBLIGATIONS
        .iter()
        .map(|entry| InvocationObligation {
            status: CoverageStatus::Complete,
            ..*entry
        })
        .collect();
    let closed = closed_inputs(&complete);
    assert!(
        completion_blockers(&closed).is_empty(),
        "nothing blocks a registered relation with every entry complete"
    );

    let open_semantic = [OPEN_SEMANTICS[0]];
    let mut one_incomplete = complete.clone();
    one_incomplete
        .last_mut()
        .expect("invocation obligations")
        .status = CoverageStatus::ComponentOnly;
    let mut one_uncovered = complete.clone();
    one_uncovered[0].status = CoverageStatus::Uncovered;
    let with_summary = |edit: &dyn Fn(&mut InventorySummary)| {
        let mut inputs = closed;
        edit(&mut inputs.summary);
        inputs
    };
    let cases: [(Blocker, CompletionInputs<'_>); 11] = [
        (
            Blocker::NoRegisteredRelation,
            CompletionInputs {
                relation: None,
                ..closed
            },
        ),
        (
            Blocker::SyscallExclusions,
            CompletionInputs {
                syscall_exclusions: &[syscalls::SYSCALL_VRF_EPOCH_SEED],
                ..closed
            },
        ),
        (
            Blocker::OpenSemantics,
            CompletionInputs {
                open_semantics: &open_semantic,
                ..closed
            },
        ),
        (
            Blocker::OpcodesIncomplete,
            with_summary(&|counts| counts.opcodes_complete -= 1),
        ),
        (
            Blocker::SyscallsIncomplete,
            with_summary(&|counts| counts.syscalls_complete -= 1),
        ),
        (
            Blocker::SyscallsIncomplete,
            // A syscall added to the ABI without a complete relation.
            with_summary(&|counts| counts.syscalls += 1),
        ),
        (
            Blocker::TrapKindsIncomplete,
            with_summary(&|counts| counts.trap_kinds_complete -= 1),
        ),
        (
            Blocker::FaultCodesIncomplete,
            with_summary(&|counts| counts.numeric_faults_complete -= 1),
        ),
        (
            Blocker::FaultCodesIncomplete,
            with_summary(&|counts| counts.pointer_abi_faults_complete -= 1),
        ),
        (
            Blocker::InvocationObligationsIncomplete,
            CompletionInputs {
                invocation_obligations: &one_incomplete,
                ..closed
            },
        ),
        (
            Blocker::InvocationObligationsIncomplete,
            CompletionInputs {
                invocation_obligations: &one_uncovered,
                ..closed
            },
        ),
    ];
    let mut exercised = BTreeSet::new();
    for (blocker, inputs) in cases {
        assert_eq!(
            completion_blockers(&inputs),
            [blocker],
            "{blocker:?} alone keeps completion open"
        );
        exercised.insert(blocker);
    }
    assert_eq!(
        exercised,
        Blocker::ALL.into_iter().collect(),
        "every blocker is exercised in isolation"
    );
    // Blockers accumulate in stable order and never mask one another.
    let several = CompletionInputs {
        relation: None,
        open_semantics: OPEN_SEMANTICS,
        invocation_obligations: INVOCATION_OBLIGATIONS,
        ..closed
    };
    assert_eq!(
        completion_blockers(&several),
        [
            Blocker::NoRegisteredRelation,
            Blocker::OpenSemantics,
            Blocker::InvocationObligationsIncomplete,
        ]
    );
    let ids: BTreeSet<_> = Blocker::ALL.iter().map(|blocker| blocker.id()).collect();
    assert_eq!(ids.len(), Blocker::COUNT);
}

/// Compare the variants of an enum declared by `source` with inventory names.
fn check_enum_variants(source: &str, header: &str, inventory: &[&str]) -> Result<(), String> {
    let declared = scan::enum_variants(source, header);
    ensure(declared == inventory, || {
        let declared: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
        let inventory: BTreeSet<&str> = inventory.iter().copied().collect();
        format!(
            "`{header}` variants and the inventory differ: {:?}",
            declared
                .symmetric_difference(&inventory)
                .collect::<Vec<_>>()
        )
    })
}

fn trap_kind_names() -> Vec<&'static str> {
    TRAP_KINDS.iter().map(TrapKindEntry::name).collect()
}

fn vm_error_names() -> Vec<&'static str> {
    VM_ERRORS.iter().map(|entry| entry.variant).collect()
}

fn numeric_fault_names() -> Vec<&'static str> {
    NUMERIC_FAULTS.iter().map(|entry| entry.name).collect()
}

fn pointer_fault_names() -> Vec<&'static str> {
    POINTER_ABI_FAULTS.iter().map(|entry| entry.name).collect()
}

#[test]
fn trap_kinds_match_the_enum_source() {
    let inventory = trap_kind_names();
    passes(check_enum_variants(
        &scan::read(ABI_ERROR),
        "pub enum VmTrapKind",
        &inventory,
    ));
    let unique: BTreeSet<_> = inventory.iter().collect();
    assert_eq!(unique.len(), TRAP_KINDS.len());
    for entry in TRAP_KINDS.iter() {
        assert_eq!(format!("{:?}", entry.kind), entry.name());
        assert!(
            entry.vm_errors().next().is_some(),
            "trap kind {} is produced by no VMError variant",
            entry.name()
        );
    }
}

#[test]
fn vm_errors_match_the_enum_source_and_trap_classification() {
    let inventory = vm_error_names();
    passes(check_enum_variants(
        &scan::read(ABI_ERROR),
        "pub enum VMError",
        &inventory,
    ));
    let samples = vm_error_samples();
    assert_eq!(
        samples
            .iter()
            .map(vm_error_variant_name)
            .collect::<Vec<_>>(),
        inventory,
        "one sample per VMError variant in declaration order"
    );
    for (sample, entry) in samples.iter().zip(VM_ERRORS.iter()) {
        let classified = IVM::classify_trap(sample);
        match entry.trap_kind {
            Some(kind) => assert_eq!(classified, kind, "{}", entry.variant),
            None => {
                assert_eq!(entry.variant, "Metered");
                assert_eq!(classified, IVM::classify_trap(sample.as_unmetered()));
            }
        }
    }
    let deferred: Vec<_> = samples
        .iter()
        .filter(|sample| sample.execution_deferral().is_some())
        .map(vm_error_variant_name)
        .collect();
    let local: Vec<_> = VM_ERRORS
        .iter()
        .filter(|entry| {
            entry.origins() == [TrapOrigin::LocalDeferral]
                || entry.origins() == [TrapOrigin::HostInvariant]
        })
        .map(|entry| entry.variant)
        .collect();
    assert_eq!(
        deferred, local,
        "node-local deferrals and host-only invariants are never provable outcomes"
    );
}

#[test]
fn every_vm_error_projects_only_completed_deterministic_faults() {
    let excluded = [
        "ExecutionDeferred",
        "AllocationDeferred",
        "HostUnavailable",
        "SyscallGasQuoteExceeded",
        "SyscallMeteringModeMismatch",
        "ContractAbort",
        "UnsupportedProgramVersion",
        "UnsupportedProgramFeatureBits",
        "UnsupportedProgramAbiVersion",
        "ProgramVectorLengthTooLarge",
        "ArtifactAbiHashMismatch",
        "GenericSyscallNotAllowed",
    ];
    let samples = vm_error_samples();
    assert_eq!(samples.len(), VM_ERROR_COUNT);
    for error in samples {
        let name = vm_error_variant_name(&error);
        assert_eq!(
            error.fault_kind().is_some(),
            !excluded.contains(&name),
            "{name}"
        );
        if error.execution_deferral().is_some() {
            assert!(
                error.fault_kind().is_none(),
                "local refusal {name} cannot be a fault"
            );
        }
        let kind = error.fault_kind();
        let wrapped = VMError::Metered {
            gas: 17,
            source: Box::new(error),
        };
        assert_eq!(wrapped.fault_kind(), kind, "metering must preserve {name}");
    }
    use iroha_data_model::executor::fault::IvmFaultKindV1;
    for tag in 1..=13 {
        let code = NumericFaultV1::from_tag(tag).unwrap();
        assert_eq!(
            VMError::NumericFault(code).fault_kind(),
            Some(IvmFaultKindV1::Numeric(code))
        );
    }
    for tag in 1..=11 {
        let code = PointerAbiFaultV1::from_tag(tag).unwrap();
        assert_eq!(
            VMError::PointerAbiFault(code).fault_kind(),
            Some(IvmFaultKindV1::PointerAbi(code))
        );
    }
}

/// Every non-test source file in the producer scope, sorted.
fn producer_scope_files() -> Vec<String> {
    let mut files = Vec::new();
    for root in VM_ERROR_PRODUCER_SCOPE {
        if root.ends_with(".rs") {
            files.push((*root).to_owned());
        } else {
            files.extend(scan::rust_files(root));
        }
    }
    // Test-only modules are gated by their parent declaration.
    files.retain(|file| {
        !file.contains("tests")
            && !VM_ERROR_PRODUCER_EXCLUSIONS
                .iter()
                .any(|excluded| file.starts_with(excluded))
    });
    files.sort();
    files.dedup();
    files
}

/// Non-test, comment-free code of one producer-scope file; empty when the
/// file never names the error type, which no construction can avoid.
fn producer_code(file: &str) -> String {
    let text = scan::read(file);
    if text.contains("VMError") {
        scan::strip_line_comments(&scan::non_test_source(&text))
    } else {
        String::new()
    }
}

/// Compare the `VMError` variants each file of `files` constructs, as read by
/// `read`, with the reviewed producer table in both directions.
fn check_vm_error_producers(files: &[String], read: &dyn Fn(&str) -> String) -> Result<(), String> {
    let variants = vm_error_names();
    let mut recorded: BTreeMap<&str, BTreeSet<String>> = VM_ERROR_PRODUCERS
        .iter()
        .map(|file| (file.path, names(file.variants())))
        .collect();
    for file in files {
        let constructed = scan::constructed_vm_errors(&read(file), &variants);
        let declared = recorded.remove(file.as_str()).unwrap_or_default();
        if let Some(variant) = constructed.difference(&declared).next() {
            return Err(format!(
                "{file} constructs VMError::{variant} without a reviewed origin; record it in VM_ERROR_PRODUCERS"
            ));
        }
        if let Some(variant) = declared.difference(&constructed).next() {
            return Err(format!(
                "{file} no longer constructs VMError::{variant}; delete the stale producer record"
            ));
        }
    }
    ensure(recorded.is_empty(), || {
        format!(
            "producer records name files outside the scanned scope: {:?}",
            recorded.keys().collect::<Vec<_>>()
        )
    })
}

#[test]
fn diagnostic_nested_call_faults_and_local_refusals_have_distinct_origins() {
    let file = VM_ERROR_PRODUCERS
        .iter()
        .find(|file| file.path == "crates/ivm/src/mock_wsv/contract_calls.rs")
        .expect("typed diagnostic calls have an explicit producer owner");
    for variant in ["CallDepthExceeded", "ReentrantCall"] {
        let origins: Vec<_> = file
            .groups
            .iter()
            .filter(|group| group.variants.contains(&variant))
            .map(|group| group.origin)
            .collect();
        assert_eq!(origins, vec![TrapOrigin::SyscallTrap]);
    }
    let origins: Vec<_> = file
        .groups
        .iter()
        .filter(|group| group.variants.contains(&"ExecutionDeferred"))
        .map(|group| group.origin)
        .collect();
    assert_eq!(origins, vec![TrapOrigin::LocalDeferral]);
}

#[test]
fn vm_error_producers_match_every_constructing_source_file() {
    let files = producer_scope_files();
    assert!(
        files.len() > VM_ERROR_PRODUCERS.len(),
        "the scope holds more files than producers"
    );
    passes(check_vm_error_producers(&files, &producer_code));
    // The table itself: sorted unique files inside the scope, origin groups
    // in stable order, sorted unique known variants.
    let paths: Vec<_> = VM_ERROR_PRODUCERS.iter().map(|file| file.path).collect();
    assert!(
        paths.windows(2).all(|pair| pair[0] < pair[1]),
        "producer files are sorted and unique"
    );
    let known = names(vm_error_names());
    let samples = vm_error_samples();
    let deferrals: BTreeMap<&str, TrapOrigin> = samples
        .iter()
        .filter(|sample| sample.execution_deferral().is_some())
        .map(|sample| {
            let origin = match sample.as_unmetered() {
                VMError::HostUnavailable
                | VMError::SyscallGasQuoteExceeded { .. }
                | VMError::SyscallMeteringModeMismatch { .. } => TrapOrigin::HostInvariant,
                _ => TrapOrigin::LocalDeferral,
            };
            (vm_error_variant_name(sample), origin)
        })
        .collect();
    let mut origins = BTreeSet::new();
    for file in VM_ERROR_PRODUCERS {
        assert!(files.contains(&file.path.to_owned()), "{}", file.path);
        assert!(!file.groups.is_empty(), "{}", file.path);
        assert!(
            file.groups
                .windows(2)
                .all(|pair| pair[0].origin < pair[1].origin),
            "{}: origin groups are unique and in stable order",
            file.path
        );
        for group in file.groups {
            origins.insert(group.origin);
            assert!(
                group.variants.windows(2).all(|pair| pair[0] < pair[1]),
                "{}: {:?} variants are sorted and unique",
                file.path,
                group.origin
            );
            for variant in group.variants {
                assert!(
                    known.contains(*variant),
                    "{}: unknown variant {variant}",
                    file.path
                );
                // Host-only invariant failures are transported as local
                // refusals too, but retain their distinct unreachable-host
                // proof obligations. Other refusal variants must have the
                // ordinary local-deferral origin. A deterministic variant
                // such as DecodeError can also arise from a host invariant;
                // it must never acquire the local-deferral classification.
                if let Some(expected) = deferrals.get(variant) {
                    assert_eq!(
                        group.origin, *expected,
                        "{}: {variant} has the exact reviewed refusal origin",
                        file.path
                    );
                } else {
                    assert_ne!(
                        group.origin,
                        TrapOrigin::LocalDeferral,
                        "{}: {variant} is not a local refusal",
                        file.path
                    );
                }
            }
        }
        assert_eq!(
            file.variants().len(),
            file.variants().iter().collect::<BTreeSet<_>>().len()
        );
    }
    assert_eq!(
        origins,
        TrapOrigin::ALL.into_iter().collect(),
        "prepare rejection, initialization, interpreter and syscall traps, host invariants, local deferrals and constructions outside the invocation are all distinguished"
    );
    // Per-variant views are derived from the one table.
    for entry in VM_ERRORS.iter() {
        let producers = entry.producers();
        let unique: BTreeSet<_> = producers
            .iter()
            .map(|producer| (producer.origin, producer.path))
            .collect();
        assert_eq!(unique.len(), producers.len(), "{}", entry.variant);
        for producer in &producers {
            let file = VM_ERROR_PRODUCERS
                .iter()
                .find(|file| file.path == producer.path)
                .expect("producer file");
            assert!(file.variants().contains(&entry.variant));
        }
    }
    // A variant without producers has none anywhere in the scope, which the
    // comparison above just established, and keeps completion open.
    let unproduced: Vec<_> = VM_ERRORS
        .iter()
        .filter(|entry| entry.producers().is_empty())
        .map(|entry| entry.variant)
        .collect();
    assert_eq!(unproduced, ["NullifierAlreadyUsed"]);
    assert!(
        OPEN_SEMANTICS
            .iter()
            .any(|entry| entry.id == "vm_error_without_producer"),
        "an unproduced variant keeps completion open"
    );
}

#[test]
fn trap_origins_distinguish_rejections_traps_invariants_and_deferrals() {
    let kind = |kind: VmTrapKind| {
        TRAP_KINDS
            .iter()
            .find(|entry| entry.kind == kind)
            .expect("inventoried trap kind")
    };
    let variant = |name: &str| {
        VM_ERRORS
            .iter()
            .find(|entry| entry.variant == name)
            .unwrap_or_else(|| panic!("inventoried variant {name}"))
    };
    use TrapOrigin::{
        HostInvariant, InitializationTrap, InterpreterTrap, LocalDeferral, OutsideInvocation,
        PrepareRejection, SyscallTrap,
    };
    for prepare_only in [
        VmTrapKind::UnsupportedProgramVersion,
        VmTrapKind::UnsupportedProgramFeatureBits,
        VmTrapKind::UnsupportedProgramAbiVersion,
        VmTrapKind::ProgramVectorLengthTooLarge,
        VmTrapKind::ArtifactAbiHashMismatch,
    ] {
        assert_eq!(kind(prepare_only).origins(), [PrepareRejection]);
        assert_eq!(
            kind(prepare_only).obligations(),
            [Obligation::StatementBinding],
            "a rejected artifact has no trace"
        );
    }
    for interpreter_only in [VmTrapKind::MissingHalt, VmTrapKind::InvalidVectorLength] {
        assert_eq!(kind(interpreter_only).origins(), [InterpreterTrap]);
    }
    for syscall_only in [
        VmTrapKind::NumericFault,
        VmTrapKind::PointerAbiFault,
        VmTrapKind::ContractAbort,
        VmTrapKind::HostOutputBudgetExceeded,
        VmTrapKind::AmxBudgetExceeded,
    ] {
        assert_eq!(kind(syscall_only).origins(), [SyscallTrap]);
    }
    for invariant in [
        VmTrapKind::SyscallGasQuoteExceeded,
        VmTrapKind::SyscallMeteringModeMismatch,
    ] {
        assert_eq!(kind(invariant).origins(), [HostInvariant]);
        assert!(!kind(invariant).obligations().contains(&Obligation::Faults));
    }
    assert_eq!(kind(VmTrapKind::Other).origins(), [LocalDeferral]);
    assert!(kind(VmTrapKind::Other).obligations().is_empty());
    // Argument preparation before the run, root-call initialization inside
    // it, the step and padding debits and the syscall quote can each run out
    // of gas.
    assert_eq!(
        kind(VmTrapKind::OutOfGas).origins(),
        [
            PrepareRejection,
            InitializationTrap,
            InterpreterTrap,
            SyscallTrap
        ]
    );
    assert_eq!(
        variant("OutOfGas").origins(),
        [
            PrepareRejection,
            InitializationTrap,
            InterpreterTrap,
            SyscallTrap
        ]
    );
    assert_eq!(variant("SyscallOutOfGas").origins(), [SyscallTrap]);
    // The heap is preflighted by argument preparation before the run and by
    // root-call initialization inside it, and allocated by syscalls; no
    // opcode allocates.
    assert_eq!(
        kind(VmTrapKind::OutOfMemory).origins(),
        [PrepareRejection, InitializationTrap, SyscallTrap]
    );
    for (name, path) in [
        ("OutOfGas", "crates/ivm/src/argument_record.rs"),
        ("OutOfGas", INTERPRETER),
        ("OutOfMemory", INTERPRETER),
        ("OutOfMemory", "crates/ivm/src/memory.rs"),
        ("PermissionDenied", CALL_RUNTIME),
        ("DecodeError", CALL_RUNTIME),
    ] {
        let producers = variant(name).producers();
        for origin in [PrepareRejection, InitializationTrap] {
            assert!(
                producers
                    .iter()
                    .any(|producer| producer.origin == origin && producer.path == path),
                "{name} lacks the {origin:?} origin in {path}"
            );
        }
    }
    // A shared cycle allowance exhausted by an earlier run is refused at
    // entry; the executor relabels a failed migration run outside any
    // invocation.
    assert_eq!(
        kind(VmTrapKind::ExceededMaxCycles).origins(),
        [InitializationTrap, InterpreterTrap, OutsideInvocation]
    );
    assert_eq!(
        kind(VmTrapKind::AssertionFailed).origins(),
        [InitializationTrap, InterpreterTrap, OutsideInvocation]
    );
    assert_eq!(
        kind(VmTrapKind::InvalidOpcode).origins(),
        [PrepareRejection, InterpreterTrap]
    );
    assert_eq!(
        kind(VmTrapKind::NotImplemented).origins(),
        [SyscallTrap, HostInvariant]
    );
    assert_eq!(
        kind(VmTrapKind::GasCostOverflow).origins(),
        [InitializationTrap, InterpreterTrap, SyscallTrap]
    );
    let ids: BTreeSet<_> = TrapOrigin::ALL.iter().map(|origin| origin.id()).collect();
    assert_eq!(ids.len(), TrapOrigin::COUNT);
    for origin in TrapOrigin::ALL {
        assert_eq!(
            origin.in_invocation(),
            matches!(origin, InitializationTrap | InterpreterTrap | SyscallTrap),
            "{origin:?}"
        );
        assert_eq!(
            origin.obligations().contains(&Obligation::Faults),
            origin.in_invocation(),
            "{origin:?}: exactly the in-invocation origins are proven terminal faults"
        );
        let unique: BTreeSet<_> = origin.obligations().iter().collect();
        assert_eq!(unique.len(), origin.obligations().len(), "{origin:?}");
    }
    // An initialization trap binds the initialized state and constrains its
    // executed padding cycles to zero.
    for required in [
        Obligation::Initialization,
        Obligation::Faults,
        Obligation::Gas,
        Obligation::Padding,
        Obligation::StatementBinding,
    ] {
        assert!(InitializationTrap.obligations().contains(&required));
    }
    assert!(LocalDeferral.obligations().is_empty());
    assert!(OutsideInvocation.obligations().is_empty());
    assert!(!HostInvariant.obligations().contains(&Obligation::Faults));
    for entry in TRAP_KINDS.iter() {
        let in_invocation = entry.origins().into_iter().any(TrapOrigin::in_invocation);
        assert_eq!(
            entry.obligations().contains(&Obligation::Faults),
            in_invocation,
            "{}: only in-invocation outcomes are proven as terminal faults",
            entry.name()
        );
    }
}

#[test]
fn numeric_and_pointer_faults_match_their_tag_decoders_and_enum_sources() {
    let numeric_source = scan::read(ABI_NUMERIC);
    let decoded: Vec<_> = (0..=u64::from(u16::MAX))
        .filter_map(NumericFaultV1::from_tag)
        .collect();
    assert_eq!(
        decoded,
        NUMERIC_FAULTS
            .iter()
            .map(|entry| entry.fault)
            .collect::<Vec<_>>(),
        "NumericFaultV1::from_tag and the inventory differ"
    );
    passes(check_enum_variants(
        &numeric_source,
        "pub enum NumericFaultV1",
        &numeric_fault_names(),
    ));
    for (index, entry) in NUMERIC_FAULTS.iter().enumerate() {
        assert_eq!(format!("{:?}", entry.fault), entry.name);
        assert_eq!(
            entry.fault.tag(),
            index as u64 + 1,
            "contiguous stable tags"
        );
        assert_eq!(
            IVM::classify_trap(&VMError::NumericFault(entry.fault)),
            VmTrapKind::NumericFault
        );
    }
    let decoded: Vec<_> = (0..=u64::from(u16::MAX))
        .filter_map(PointerAbiFaultV1::from_tag)
        .collect();
    assert_eq!(
        decoded,
        POINTER_ABI_FAULTS
            .iter()
            .map(|entry| entry.fault)
            .collect::<Vec<_>>(),
        "PointerAbiFaultV1::from_tag and the inventory differ"
    );
    passes(check_enum_variants(
        &numeric_source,
        "pub enum PointerAbiFaultV1",
        &pointer_fault_names(),
    ));
    for (index, entry) in POINTER_ABI_FAULTS.iter().enumerate() {
        assert_eq!(format!("{:?}", entry.fault), entry.name);
        assert_eq!(
            entry.fault.tag(),
            index as u64 + 1,
            "contiguous stable tags"
        );
        assert_eq!(
            IVM::classify_trap(&VMError::PointerAbiFault(entry.fault)),
            VmTrapKind::PointerAbiFault
        );
    }
    assert!(NumericFaultEntry::OBLIGATIONS.contains(&Obligation::Faults));
    assert!(PointerAbiFaultEntry::OBLIGATIONS.contains(&Obligation::Pointers));
    let counts = summary();
    assert_eq!(counts.numeric_faults, 13);
    assert_eq!(counts.pointer_abi_faults, 11);
}

#[test]
fn component_sources_cover_every_non_test_proof_module() {
    let proof_prefix = PROOF_ROOT.strip_suffix(".rs").expect("proof root file");
    let walked: BTreeSet<String> = scan::module_files(PROOF_ROOT).into_iter().collect();
    let mut owned = BTreeMap::new();
    for entry in COMPONENTS {
        assert!(!entry.sources.is_empty(), "{}", entry.id);
        for source in entry.sources {
            assert!(
                scan::repo_root().join(source).is_file(),
                "{}: missing source {source}",
                entry.id
            );
            assert!(
                owned.insert((*source).to_owned(), entry.id).is_none(),
                "{source} is owned by two components"
            );
        }
    }
    let owned_proof: BTreeSet<String> = owned
        .keys()
        .filter(|source| source.starts_with(proof_prefix))
        .cloned()
        .collect();
    assert_eq!(
        walked, owned_proof,
        "every non-test module below {PROOF_ROOT} belongs to exactly one inventoried component"
    );
    let ids: BTreeSet<_> = COMPONENTS.iter().map(|entry| entry.id).collect();
    assert_eq!(
        ids.len(),
        COMPONENTS.len(),
        "component identifiers are unique"
    );
    for entry in COMPONENTS {
        assert_eq!(component(entry.id), Some(entry));
    }
    assert!(component("missing").is_none());
}

/// Compare the opcode, trap and syscall tokens of a component's sources, as
/// returned by `read`, with its recorded drift guard.
fn check_component_tokens(
    entry: &ProofComponent,
    read: &dyn Fn(&str) -> String,
) -> Result<(), String> {
    let mut opcodes = BTreeSet::new();
    let mut traps = BTreeSet::new();
    for source in entry.sources {
        let text = read(source);
        opcodes.extend(scan::opcode_tokens(&text).into_iter().map(|(_, name)| name));
        traps.extend(scan::tokens_after(&text, "VmTrapKind::"));
        ensure(
            scan::tokens_after(&text, "SYSCALL_").is_empty()
                && !text.contains("wide::system::SCALL")
                && !text.contains("wide::system::SYSTEM"),
            || format!("{source} now references a syscall; record its relation and coverage"),
        )?;
    }
    let referenced = names(entry.referenced_opcodes.iter().copied());
    ensure(opcodes == referenced, || {
        format!(
            "{}: opcode constants referenced by its sources changed ({:?}); review its coverage claims",
            entry.id,
            opcodes
                .symmetric_difference(&referenced)
                .collect::<Vec<_>>()
        )
    })?;
    ensure(
        traps == names(entry.traps.iter().map(|kind| trap_kind_name(*kind))),
        || {
            format!(
                "{}: trap kinds referenced by its sources changed ({traps:?}); review its coverage claims",
                entry.id
            )
        },
    )
}

#[test]
fn component_token_references_match_their_sources() {
    for entry in COMPONENTS {
        passes(check_component_tokens(entry, &|source| {
            scan::read_non_test(source)
        }));
        for name in entry.referenced_opcodes {
            assert!(
                OPCODES.iter().any(|opcode| opcode.name == *name),
                "{}: referenced opcode {name} is not admitted",
                entry.id
            );
        }
    }
}

/// The completeness checks must fail when the source gains or loses an
/// opcode, syscall, trap kind, error variant or fault that the inventory does
/// not mirror. Sources are mutated in memory only; no file is written.
#[test]
fn mutated_sources_fail_every_completeness_check() {
    // Opcodes: a newly declared admitted-module constant changes the count
    // and the set; a removed constant leaves a stale inventory entry.
    let instruction = scan::read(ABI_INSTRUCTION);
    rejects(
        check_opcode_constants(&insert_after(
            &instruction,
            "pub const MEAN: u8 = 0x2A;\n",
            "        pub const BRAND_NEW: u8 = 0x2B;\n",
        )),
        "91 admitted opcode constants",
    );
    rejects(
        check_opcode_constants(&remove_once(&instruction, "pub const MEAN: u8 = 0x2A;\n")),
        "89 admitted opcode constants",
    );
    rejects(
        check_opcode_constants(&insert_after(
            &instruction,
            "pub const VALIDATE_FORMAT: u8 = 0x9F;\n",
            "        pub const BRAND_NEW: u8 = 0x8F;\n",
        )),
        "reserved ISO 20022 opcodes differ",
    );

    // Interpreter: a new dispatch arm, a new direct trap and a new fallible
    // helper each change the inventoried fault surface.
    let interpreter = scan::read_non_test(INTERPRETER);
    let add_arm = "                    instruction::wide::arithmetic::ADD => {\n";
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            "                match wide_op {\n",
            "                    instruction::wide::arithmetic::BRAND_NEW => {\n                        continue;\n                    }\n",
        )),
        "BRAND_NEW",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            add_arm,
            "                        return Err(VMError::OutOfMemory);\n",
        )),
        "direct traps of ADD changed",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            add_arm,
            "                        self.brand_new_helper()?;\n",
        )),
        "fallible helpers of ADD changed",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            "// Fetch-Decode-Execute loop\n",
            "                return Err(VMError::DecodeError);\n",
        )),
        "direct traps of run phase `step_preamble` changed",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            "// Fetch-Decode-Execute loop\n",
            "                self.brand_new_step_check()?;\n",
        )),
        "fallible helpers of run phase `step_preamble` changed",
    );

    // Invocation entry and the terminal block after the loop: a new trap, a
    // new propagated helper, a result returned without `?` and a new stored
    // error each change the inventoried phase.
    let entry_anchor = "        let invocation_trace = self.begin_trace_invocation()?;\n";
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            entry_anchor,
            "        self.brand_new_entry_check()?;\n",
        )),
        "fallible helpers of run phase `invocation_entry` changed",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            entry_anchor,
            "        if self.cycles > 0 { return Err(VMError::DecodeError); }\n",
        )),
        "direct traps of run phase `invocation_entry` changed",
    );
    let terminal_anchor = "            self.commit_memory_after_run_if_needed();\n";
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            terminal_anchor,
            "            if self.cycles == 0 { return Err(VMError::DecodeError); }\n",
        )),
        "direct traps of run phase `terminal` changed",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            terminal_anchor,
            "            self.brand_new_terminal_check()?;\n",
        )),
        "fallible helpers of run phase `terminal` changed",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            terminal_anchor,
            "            if self.halted { return self.brand_new_terminal_result(); }\n",
        )),
        "calls of run phase `terminal` changed",
    );
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            terminal_anchor,
            "            if let Some(stored) = self.other_error.clone() { return Err(stored); }\n",
        )),
        "returned errors of run phase `terminal` changed",
    );
    rejects(
        check_interpreter_dispatch(&remove_once(
            &interpreter,
            "self.contract_abort_error.clone()",
        )),
        "result source `contract_abort_error` of run phase `terminal` is gone",
    );

    // Root-call initialization: a new trap or helper inside `begin_root_call`.
    let call_runtime = scan::read_non_test(CALL_RUNTIME);
    let root_anchor = "    pub(super) fn begin_root_call(&mut self, host: &mut dyn IVMHost) -> Result<(), VMError> {\n";
    rejects(
        check_root_call_initialization(&insert_after(
            &call_runtime,
            root_anchor,
            "        if self.pc > 9 { return Err(VMError::OutOfMemory); }\n",
        )),
        "direct traps of run phase `root_call_initialization` changed",
    );
    rejects(
        check_root_call_initialization(&insert_after(
            &call_runtime,
            root_anchor,
            "        self.brand_new_root_check()?;\n",
        )),
        "fallible helpers of run phase `root_call_initialization` changed",
    );

    // Privacy tags: an arm that starts touching a tag, and an arm that reaches
    // the tag surface through a helper the inventory does not name.
    rejects(
        check_interpreter_dispatch(&insert_after(
            &interpreter,
            "                    instruction::wide::control::JMP => {\n",
            "                        self.registers.set_tag(1, false);\n",
        )),
        "privacy-tag surface of JMP changed",
    );
    rejects(
        check_interpreter_dispatch(&format!(
            "{}\nimpl IVM {{\n    fn brand_new_tag_helper(&mut self, rd: usize) {{\n        self.registers.set_tag(rd, false);\n    }}\n}}\n",
            insert_after(
                &interpreter,
                add_arm,
                "                        self.brand_new_tag_helper(rd);\n",
            )
        )),
        "privacy helpers called by interpreter arms changed",
    );
    rejects(
        check_interpreter_dispatch(&remove_once(
            &interpreter,
            "        self.validate_syscall_privacy(number)?;\n",
        )),
        "execute_reserved_syscall no longer calls validate_syscall_privacy",
    );

    // Producers: a construction without a reviewed origin, in a recorded or
    // an unrecorded file, and a record whose construction is gone. A match
    // arm or `matches!` pattern is not a construction.
    let files = producer_scope_files();
    let codes: BTreeMap<&str, String> = files
        .iter()
        .map(|file| (file.as_str(), producer_code(file)))
        .collect();
    let with = |target: &'static str, mutation: &dyn Fn(&str) -> String| {
        assert!(
            codes.contains_key(target),
            "{target} is in the producer scope"
        );
        check_vm_error_producers(&files, &|file| {
            if file == target {
                mutation(&codes[file])
            } else {
                codes[file].clone()
            }
        })
    };
    rejects(
        with(CALL_RUNTIME, &|code| {
            format!("{code}\nfn brand_new() -> VMError {{ VMError::OutOfMemory }}\n")
        }),
        "crates/ivm/src/call_runtime.rs constructs VMError::OutOfMemory without a reviewed origin",
    );
    rejects(
        with("crates/ivm/src/gas.rs", &|code| {
            format!("{code}\nfn brand_new() -> crate::VMError {{ crate::VMError::OutOfGas }}\n")
        }),
        "crates/ivm/src/gas.rs constructs VMError::OutOfGas without a reviewed origin",
    );
    rejects(
        with("crates/ivm/src/gas.rs", &|code| {
            format!("{code}\nfn brand_new() -> crate::VMError {{ crate::VMError::brand_new(1) }}\n")
        }),
        "helper:brand_new",
    );
    rejects(
        with("crates/ivm/src/contract_return_stack.rs", &|code| {
            code.replace("VMError::AssertionFailed", "other_error()")
        }),
        "crates/ivm/src/contract_return_stack.rs no longer constructs VMError::AssertionFailed",
    );
    passes(with("crates/ivm/src/gas.rs", &|code| {
        format!(
            "{code}\nfn is_out_of_gas(error: &crate::VMError) -> bool {{\n    matches!(error, crate::VMError::OutOfGas)\n}}\n"
        )
    }));

    // Syscalls: a new or a removed SYSCALL_* constant is neither inventoried
    // nor host-private.
    let syscall_source = scan::read(ABI_SYSCALLS);
    rejects(
        check_syscall_constants(&format!(
            "{syscall_source}\npub const SYSCALL_BRAND_NEW: u32 = 0x2D;\n"
        )),
        "BRAND_NEW",
    );
    rejects(
        check_syscall_constants(&remove_once(
            &syscall_source,
            "pub const SYSCALL_EXIT: u32 = 0x01;\n",
        )),
        "EXIT",
    );

    // Trap kinds, error variants and stable fault codes.
    let error_source = scan::read(ABI_ERROR);
    let numeric_source = scan::read(ABI_NUMERIC);
    for (source, header, inventory, anchor, removed) in [
        (
            &error_source,
            "pub enum VmTrapKind",
            trap_kind_names(),
            "pub enum VmTrapKind {\n",
            "    MissingHalt,\n",
        ),
        (
            &error_source,
            "pub enum VMError",
            vm_error_names(),
            "pub enum VMError {\n",
            "    HostUnavailable,\n",
        ),
        (
            &numeric_source,
            "pub enum NumericFaultV1",
            numeric_fault_names(),
            "pub enum NumericFaultV1 {\n",
            "    DivisionByZero = 3,\n",
        ),
        (
            &numeric_source,
            "pub enum PointerAbiFaultV1",
            pointer_fault_names(),
            "pub enum PointerAbiFaultV1 {\n",
            "    WrongType = 4,\n",
        ),
    ] {
        passes(check_enum_variants(source, header, &inventory));
        rejects(
            check_enum_variants(
                &insert_after(source, anchor, "    BrandNew,\n"),
                header,
                &inventory,
            ),
            "BrandNew",
        );
        let variant = removed.trim().trim_end_matches(',');
        let variant = variant.split(' ').next().unwrap_or(variant);
        rejects(
            check_enum_variants(&remove_once(source, removed), header, &inventory),
            variant,
        );
    }

    // Proof components: a source that starts naming another opcode, trap or
    // syscall, or stops naming one, requires a coverage review.
    let segment = component("public_scalar_segment").expect("scalar segment");
    let mutate = |mutation: &dyn Fn(&str) -> String| {
        check_component_tokens(segment, &|source| {
            let text = scan::read_non_test(source);
            if source.ends_with("ivm_step_air/trace.rs") {
                mutation(&text)
            } else {
                text
            }
        })
    };
    rejects(
        mutate(&|text| format!("{text}\nconst NEW: u8 = wide::crypto::SHA256BLOCK;\n")),
        "SHA256BLOCK",
    );
    rejects(
        mutate(&|text| text.replace("wide::arithmetic::GCD", "wide::arithmetic::ADD")),
        "GCD",
    );
    rejects(
        mutate(&|text| format!("{text}\nconst NEW: VmTrapKind = VmTrapKind::MemoryFault;\n")),
        "MemoryFault",
    );
    rejects(
        mutate(&|text| format!("{text}\nconst NEW: u32 = ivm::syscalls::SYSCALL_STATE_GET;\n")),
        "references a syscall",
    );
}

#[test]
fn component_claims_are_admitted_bounded_and_unregistered() {
    for entry in COMPONENTS {
        assert!(
            !entry.registered,
            "{} must not claim registration",
            entry.id
        );
        assert!(!entry.restrictions.is_empty(), "{}", entry.id);
        assert!(!entry.substrate.is_empty(), "{}", entry.id);
        let unique: BTreeSet<_> = entry.opcodes.iter().map(|covered| covered.opcode).collect();
        assert_eq!(unique.len(), entry.opcodes.len(), "{}", entry.id);
        for covered in entry.opcodes {
            assert!(
                opcode_entry(covered.opcode).is_some(),
                "{}: covered opcode 0x{:02x} is not admitted",
                entry.id,
                covered.opcode
            );
        }
        for fact in entry.geometry {
            assert_eq!(
                scan::const_literal(&scan::read(fact.path), fact.constant),
                Some(fact.value),
                "{}: {} in {} changed",
                entry.id,
                fact.constant,
                fact.path
            );
        }
    }
    // The native component's scalar coverage is bounded by the producer's
    // operand-observation lookup; this is not AIR acceptance evidence.
    let native = component("native_invocation").expect("native component");
    let observed: BTreeSet<u8> = (0..=u8::MAX)
        .filter(|opcode| {
            crate::execution_packets::public_scalar_operands(u32::from(*opcode) << 24).is_some()
        })
        .collect();
    assert_eq!(observed.len(), 31);
    let mut expected = observed;
    expected.extend([
        wide::memory::LDI64,
        wide::memory::LOAD64,
        wide::memory::STORE64,
        wide::control::JALR,
    ]);
    assert_eq!(
        native
            .opcodes
            .iter()
            .map(|covered| covered.opcode)
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert!(
        native
            .opcodes
            .iter()
            .all(|covered| covered.restriction.is_some())
    );
    assert_eq!(crate::execution_packets::MAX_STEPS, 64);
    assert_eq!(crate::execution_packets::PACKET_SLOTS, 16_384);
    assert_eq!(crate::execution_packets::RETURN_CELLS, 4_097);
    assert_eq!(crate::execution_packets::ROOT_SLOTS, 64);
    assert_eq!(
        crate::execution_packets::INSTRUCTION_WINDOWS,
        crate::execution_packets::MAX_STEPS + 1
    );
    // The protected callable-depth limit and the nested-contract host limit
    // are different bounds owned by different crates.
    assert_eq!(crate::limits::MAX_CONTRACT_CALL_DEPTH, 1024);
    assert_eq!(
        scan::const_literal(&scan::read(CORE_HOST), "MAX_NESTED_CONTRACT_CALL_DEPTH"),
        Some(32)
    );
    let restricted = |id: &str, opcode: u8| {
        component(id)
            .and_then(|entry| {
                entry
                    .opcodes
                    .iter()
                    .find(|covered| covered.opcode == opcode)
            })
            .and_then(|covered| covered.restriction)
    };
    assert_eq!(
        restricted("public_scalar_segment", wide::control::JAL),
        Some("rd = r0 only; linked calls are excluded")
    );
    assert!(restricted("private_dispatch", wide::control::JALR).is_some());
    assert!(restricted("private_memory", wide::memory::LOAD128).is_some());
}

#[test]
fn proof_components_are_unregistered_and_admission_is_closed() {
    let module = scan::read(PROOF_MODULE);
    assert!(
        module.contains("\nmod ivm_step_air;\n") && !module.contains("pub mod ivm_step_air"),
        "the IVM step chips became public; record the registered relation"
    );
    assert!(
        !scan::read(PROOF_REGISTRY).contains("ivm_step_air"),
        "the execution-proof registry now references the IVM chips; record the registration"
    );
    assert_eq!(PRODUCTION_ADMISSION, "closed");
    let admission = OPEN_SEMANTICS
        .iter()
        .find(|entry| entry.id == "no_registered_invocation_relation")
        .expect("admission record");
    assert_eq!(admission.evidence.len(), 1);
    assert!(
        scan::read_non_test(admission.evidence[0].path).contains(admission.evidence[0].symbol),
        "IvmProved verification no longer rejects unconditionally; update PRODUCTION_ADMISSION and COMPLETE_RELATION"
    );
}

/// Check every evidence citation of `entry` against the non-test source that
/// `read` returns for its file.
fn check_open_semantic(entry: &OpenSemantic, read: &dyn Fn(&str) -> String) -> Result<(), String> {
    ensure(!entry.evidence.is_empty(), || {
        format!("open semantic `{}` cites no evidence", entry.id)
    })?;
    for citation in entry.evidence {
        ensure(read(citation.path).contains(citation.symbol), || {
            format!(
                "open semantic `{}` is stale: {} no longer contains `{}`; correct the record, and delete it only once none of its evidence remains",
                entry.id, citation.path, citation.symbol
            )
        })?;
    }
    Ok(())
}

#[test]
fn open_semantics_are_unique_and_still_evidenced() {
    let ids: BTreeSet<_> = OPEN_SEMANTICS.iter().map(|entry| entry.id).collect();
    assert_eq!(ids.len(), OPEN_SEMANTICS.len());
    let read = |path: &str| scan::read_non_test(path);
    for entry in OPEN_SEMANTICS {
        passes(check_open_semantic(entry, &read));
        let unique: BTreeSet<_> = entry
            .evidence
            .iter()
            .map(|citation| (citation.path, citation.symbol))
            .collect();
        assert_eq!(unique.len(), entry.evidence.len(), "{}", entry.id);
    }
    let record = |id: &str| {
        OPEN_SEMANTICS
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("open semantic `{id}`"))
    };
    for name in [
        "SM3_HASH",
        "SM2_VERIFY",
        "SM4_GCM_SEAL",
        "SM4_GCM_OPEN",
        "SM4_CCM_SEAL",
        "SM4_CCM_OPEN",
    ] {
        assert!(SYSCALLS.iter().any(|entry| entry.name == name), "{name}");
        assert!(record("sm_syscall_local_switch").subject.contains(name));
    }
    // The SM record names all three switches and cites each one, so removing
    // only the host flag, only the Cargo feature gate or only the
    // configuration derivation leaves a failing citation behind.
    let sm = record("sm_syscall_local_switch");
    for term in ["`sm_enabled`", "`sm` Cargo feature", "`allowed_signing`"] {
        assert!(sm.reason.contains(term), "SM record omits {term}");
    }
    let cited = |path: &str, symbol: &str| {
        sm.evidence
            .iter()
            .any(|citation| citation.path == path && citation.symbol.contains(symbol))
    };
    assert!(cited("crates/ivm/src/core_host.rs", "!self.sm_enabled"));
    assert!(cited(
        "crates/iroha_config/src/parameters/actual.rs",
        "cfg(not(feature = \"sm\"))"
    ));
    assert!(cited(
        "crates/iroha_config/src/parameters/actual.rs",
        "Algorithm::Sm2"
    ));
    assert!(cited(CORE_HOST, "sm_helpers_enabled()"));
    for citation in sm.evidence {
        let text = scan::read_non_test(citation.path);
        rejects(
            check_open_semantic(sm, &|path| {
                if path == citation.path {
                    text.replace(citation.symbol, "")
                } else {
                    scan::read_non_test(path)
                }
            }),
            citation.symbol,
        );
    }
    // Node-local limits that change an outcome are open, not silently bound.
    for (id, needle) in [
        (
            "shared_cycle_allowance_node_local",
            "pipeline.quarantine_tx_max_cycles",
        ),
        (
            "host_output_limits_node_local",
            "pipeline.overlay_max_instructions",
        ),
        (
            "host_output_limits_node_local",
            "pipeline.overlay_max_bytes",
        ),
        ("host_cycle_limit_override", "set_max_cycles("),
    ] {
        assert!(
            record(id)
                .evidence
                .iter()
                .any(|citation| citation.symbol.contains(needle)),
            "{id} cites {needle}"
        );
    }
    assert!(
        INVOCATION_OBLIGATIONS
            .iter()
            .any(|entry| entry.id == "statement.execution_limits"
                && entry.status == CoverageStatus::Uncovered),
        "execution limits are an open statement obligation"
    );
    assert_eq!(
        SYSCALLS
            .iter()
            .filter(|entry| entry.relation == SyscallRelation::SoraCloud)
            .count(),
        SYSCALLS
            .iter()
            .filter(|entry| entry.name.starts_with("SORACLOUD_"))
            .count()
    );
}

#[test]
fn coverage_is_derived_from_components_and_never_complete() {
    let counts = summary();
    assert_eq!(counts.opcodes_uncovered + counts.opcodes_component_only, 90);
    assert_eq!(counts.opcodes_component_only, 58);
    assert_eq!(counts.opcodes_uncovered, 32);
    assert_eq!(counts.components, COMPONENTS.len());
    for entry in OPCODES.iter() {
        let covered = components_for_opcode(entry.opcode).next().is_some();
        assert_eq!(
            opcode_coverage(entry.opcode),
            if covered {
                CoverageStatus::ComponentOnly
            } else {
                CoverageStatus::Uncovered
            },
            "{}",
            entry.name
        );
    }
    assert_eq!(
        opcode_coverage(wide::iso20022::MSG_CREATE),
        CoverageStatus::Uncovered
    );
    let uncovered: BTreeSet<_> = OPCODES
        .iter()
        .filter(|entry| opcode_coverage(entry.opcode) == CoverageStatus::Uncovered)
        .map(|entry| entry.name)
        .collect();
    for name in [
        "SCALL",
        "SYSTEM",
        "LDLIT",
        "JR",
        "HALT",
        "SETVL",
        "VADD32",
        "PARBEGIN",
        "PAREND",
        "SHA256BLOCK",
        "POSEIDON2",
        "ED25519VERIFY",
        "ASSERT",
        "FADD",
    ] {
        assert!(uncovered.contains(name), "{name} has no proof component");
    }
    for entry in OPCODES.iter() {
        let uncovered_family = matches!(
            entry.family,
            OpcodeFamily::Vector | OpcodeFamily::Parallel | OpcodeFamily::Crypto | OpcodeFamily::Zk
        ) || entry.effect == StepEffect::HostCall;
        if uncovered_family {
            assert_eq!(
                opcode_coverage(entry.opcode),
                CoverageStatus::Uncovered,
                "{}",
                entry.name
            );
        }
    }
    for entry in TRAP_KINDS.iter() {
        let expected = if matches!(
            entry.kind,
            VmTrapKind::OutOfGas | VmTrapKind::AssertionFailed
        ) {
            CoverageStatus::ComponentOnly
        } else {
            CoverageStatus::Uncovered
        };
        assert_eq!(trap_coverage(entry.kind), expected, "{}", entry.name());
        assert_eq!(
            components_for_trap(entry.kind).count(),
            usize::from(expected == CoverageStatus::ComponentOnly)
        );
    }
    let ids: BTreeSet<_> = INVOCATION_OBLIGATIONS
        .iter()
        .map(|entry| entry.id)
        .collect();
    assert_eq!(ids.len(), INVOCATION_OBLIGATIONS.len());
    // ABI version, code hash and manifest ABI hash are separate obligations,
    // each cited at the symbol that enforces it today.
    for id in [
        "statement.abi_version",
        "statement.code_hash",
        "statement.manifest_abi_hash",
    ] {
        let entry = INVOCATION_OBLIGATIONS
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("missing invocation obligation {id}"));
        assert_eq!(entry.obligation, Obligation::StatementBinding);
        assert!(!entry.citations.is_empty(), "{id} cites its source symbol");
    }
    for entry in INVOCATION_OBLIGATIONS {
        assert_ne!(entry.status, CoverageStatus::Complete, "{}", entry.id);
        assert_eq!(
            entry.components.is_empty(),
            entry.status == CoverageStatus::Uncovered,
            "{}",
            entry.id
        );
        for citation in entry.citations {
            assert!(
                scan::read_non_test(citation.path).contains(citation.symbol),
                "{}: {} no longer contains `{}`",
                entry.id,
                citation.path,
                citation.symbol
            );
        }
        for id in entry.components {
            let holder =
                component(id).unwrap_or_else(|| panic!("{}: unknown component {id}", entry.id));
            assert!(
                holder.substrate.contains(&entry.obligation)
                    || entry.obligation == Obligation::StatementBinding,
                "{}: {id} holds no {:?} substrate",
                entry.id,
                entry.obligation
            );
        }
    }
}

#[test]
fn obligation_classes_cover_the_acceptance_terms_and_are_all_used() {
    let ids: Vec<_> = Obligation::ALL
        .iter()
        .map(|obligation| obligation.id())
        .collect();
    let unique: BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), Obligation::COUNT);
    for acceptance in [
        "typed_values",
        "initialization",
        "memory_ordering",
        "pointers",
        "calls",
        "copyback",
        "faults",
        "gas",
        "padding",
        "vector",
        "parallel",
        "precompile",
        "continuation",
        "proof_composition",
        "vm_recursion",
        "private_masking",
    ] {
        assert!(
            ids.contains(&acceptance),
            "missing obligation class {acceptance}"
        );
    }
    let mut used = BTreeSet::new();
    for entry in OPCODES.iter() {
        used.extend(entry.obligations.iter().copied());
    }
    for relation in SyscallRelation::ALL {
        used.extend(relation.obligations().iter().copied());
    }
    for origin in TrapOrigin::ALL {
        used.extend(origin.obligations().iter().copied());
    }
    for phase in RUN_PHASES {
        used.extend(phase.obligations.iter().copied());
    }
    used.extend(INVOCATION_OBLIGATIONS.iter().map(|entry| entry.obligation));
    assert_eq!(
        used,
        Obligation::ALL.into_iter().collect(),
        "every obligation class is engaged by an inventoried entry"
    );
    for obligation in Obligation::ALL {
        assert!(!obligation.requirement().is_empty());
    }
    let statuses: BTreeSet<_> = [
        CoverageStatus::Uncovered,
        CoverageStatus::ComponentOnly,
        CoverageStatus::Complete,
    ]
    .map(CoverageStatus::id)
    .into();
    assert_eq!(statuses.len(), 3);
}

#[test]
fn rendered_inventory_matches_the_tracked_artifact() {
    let rendered = render_inventory_json();
    assert_eq!(
        rendered,
        render_inventory_json(),
        "rendering is deterministic"
    );
    let value: norito::json::Value =
        norito::json::from_str(&rendered).expect("rendered inventory is valid JSON");
    let field = |key: &str| {
        value
            .as_object()
            .and_then(|object| object.get(key))
            .unwrap_or_else(|| panic!("rendered inventory lacks `{key}`"))
    };
    let rows = |key: &str| field(key).as_array().map_or(0, Vec::len);
    assert_eq!(
        field("schema"),
        &norito::json::Value::from(INVENTORY_SCHEMA)
    );
    assert_eq!(field("complete_relation"), &norito::json::Value::Null);
    assert_eq!(field("completion_open"), &norito::json::Value::from(true));
    assert_eq!(
        rows("completion_blockers"),
        completion_blockers(&CompletionInputs::current()).len()
    );
    assert_eq!(rows("default_syscall_exclusions"), 0);
    assert_eq!(rows("run_phases"), RUN_PHASES.len());
    for key in ["privacy_tag_surface", "vm_error_producer_scope"] {
        assert!(field(key).as_object().is_some(), "{key} is an object");
    }
    for entry in OPEN_SEMANTICS {
        for citation in entry.evidence {
            assert!(
                rendered.contains(
                    &norito::json::to_json(&norito::json::Value::from(citation.symbol))
                        .expect("JSON string")
                ),
                "{}: evidence `{}` is rendered",
                entry.id,
                citation.symbol
            );
        }
    }
    for file in VM_ERROR_PRODUCERS {
        assert!(rendered.contains(file.path), "{} is rendered", file.path);
    }
    assert_eq!(rows("opcodes"), 90);
    assert_eq!(rows("reserved_opcodes"), RESERVED_OPCODES.len());
    assert_eq!(rows("syscalls"), syscalls::abi_syscall_list().len());
    assert_eq!(rows("host_private_syscalls"), HOST_PRIVATE_SYSCALLS.len());
    assert_eq!(rows("syscall_relations"), SyscallRelation::COUNT);
    assert_eq!(rows("trap_kinds"), TRAP_KINDS.len());
    assert_eq!(rows("trap_origins"), TrapOrigin::COUNT);
    assert_eq!(rows("vm_errors"), VM_ERRORS.len());
    assert_eq!(rows("numeric_faults"), NUMERIC_FAULTS.len());
    assert_eq!(rows("pointer_abi_faults"), POINTER_ABI_FAULTS.len());
    assert_eq!(rows("components"), COMPONENTS.len());
    assert_eq!(rows("obligations"), Obligation::COUNT);
    assert_eq!(rows("invocation_obligations"), INVOCATION_OBLIGATIONS.len());
    assert_eq!(rows("open_semantics"), OPEN_SEMANTICS.len());
    // No entry is complete today, in any status column of any section. A
    // text search cannot say this: `complete` is also the name of a helper
    // the terminal run phase propagates.
    let complete = norito::json::Value::from(CoverageStatus::Complete.id());
    let mut statuses = 0_usize;
    for (section, columns) in [
        ("opcodes", &["coverage"][..]),
        ("syscalls", &["coverage", "result", "trap", "statement"][..]),
        ("trap_kinds", &["coverage"][..]),
        ("numeric_faults", &["coverage"][..]),
        ("pointer_abi_faults", &["coverage"][..]),
        ("invocation_obligations", &["status"][..]),
    ] {
        for row in field(section).as_array().expect("section rows") {
            for column in columns {
                let status = row
                    .as_object()
                    .and_then(|object| object.get(*column))
                    .unwrap_or_else(|| panic!("{section} row lacks `{column}`"));
                assert_ne!(status, &complete, "{section}: no entry is complete today");
                statuses += 1;
            }
        }
    }
    assert_eq!(
        statuses,
        90 + 4 * SYSCALLS.len()
            + TRAP_KINDS.len()
            + NUMERIC_FAULTS.len()
            + POINTER_ABI_FAULTS.len()
            + INVOCATION_OBLIGATIONS.len()
    );
    let tracked = scan::read(INVENTORY_ARTIFACT_PATH);
    assert!(
        tracked == rendered,
        "{INVENTORY_ARTIFACT_PATH} is stale; regenerate it with \
         `cargo run --locked -p ivm --features dev-tools --bin gen_proof_coverage_inventory -- --write`"
    );
}
