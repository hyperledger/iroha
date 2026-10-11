use crate::{ContractArtifactError, DecodedOp};
use iroha_data_model::smart_contract::manifest::{
    AccessSetHints, DynamicAccessHint, EntryPointKind, KotobaTranslationEntry,
    validate_contract_permission_table,
};
use ivm_abi::metadata::{
    CONTRACT_FEATURE_BIT_VECTOR, CONTRACT_FEATURE_BIT_ZK, CONTRACT_FEATURE_KNOWN_BITS,
    EmbeddedContractInterfaceV1, EmbeddedEntrypointDescriptor, EmbeddedStateDescriptor,
    EmbeddedStateType, ProgramMetadata, mode,
};
use ivm_abi::state_value::{
    MAX_STATE_VALUE_NODES, MAX_STATE_VALUE_SCHEMA_BYTES,
    admissible_state_value_schema_for_embedded_type_v1,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationProfile {
    Production,
    KotoTest,
}
impl ValidationProfile {
    fn allows_syscall(self, number: u32) -> bool {
        ivm_abi::syscalls::is_syscall_allowed(ivm_abi::SyscallPolicy::AbiV1, number)
            || (self == Self::KotoTest && ivm_abi::syscalls::is_koto_test_syscall(number))
    }
}
pub fn validate_contract_interface(
    metadata: &ProgramMetadata,
    contract_interface: &EmbeddedContractInterfaceV1,
    decoded: &[DecodedOp],
    profile: ValidationProfile,
) -> Result<Vec<String>, ContractArtifactError> {
    if !is_canonical_seiyaku_name(&contract_interface.seiyaku_name) {
        return Err(ContractArtifactError::invalid(
            "CNTR seiyaku_name must be a canonical Kotodama V1 identifier",
        ));
    }
    let fingerprint = contract_interface.compiler_fingerprint.trim();
    if fingerprint.is_empty() {
        return Err(ContractArtifactError::invalid(
            "CNTR compiler_fingerprint must not be empty",
        ));
    }
    let features_bitmap = contract_interface.features_bitmap;
    if features_bitmap & !CONTRACT_FEATURE_KNOWN_BITS != 0 {
        return Err(ContractArtifactError::invalid(format!(
            "CNTR features_bitmap contains unsupported bits 0x{:x}",
            features_bitmap & !CONTRACT_FEATURE_KNOWN_BITS
        )));
    }
    let zk_declared = features_bitmap & CONTRACT_FEATURE_BIT_ZK != 0;
    let vector_declared = features_bitmap & CONTRACT_FEATURE_BIT_VECTOR != 0;
    let zk_enabled = metadata.mode & mode::ZK != 0;
    let vector_enabled = metadata.mode & mode::VECTOR != 0;
    if zk_declared != zk_enabled {
        return Err(ContractArtifactError::invalid(
            "CNTR features_bitmap does not match metadata ZK mode",
        ));
    }
    if vector_declared != vector_enabled {
        return Err(ContractArtifactError::invalid(
            "CNTR features_bitmap does not match metadata VECTOR mode",
        ));
    }
    if !validate_contract_permission_table(&contract_interface.permissions)
        || contract_interface
            .permissions
            .iter()
            .any(|declaration| !is_canonical_seiyaku_name(declaration.name.as_ref()))
    {
        return Err(ContractArtifactError::invalid(
            "CNTR permission declarations must have canonical names in sorted unique order",
        ));
    }
    if !iroha_data_model::smart_contract::event::validate_contract_event_table(
        &contract_interface.events,
    ) {
        return Err(ContractArtifactError::invalid(
            "CNTR events must be sorted unique named public structs within the declaration bounds",
        ));
    }
    validate_access_set_hints(contract_interface.access_set_hints.as_ref())?;
    validate_kotoba_entries(&contract_interface.kotoba)?;
    validate_state_descriptors(contract_interface)?;
    validate_dynamic_access_hint_state_maps(
        contract_interface.access_set_hints.as_ref(),
        &contract_interface.states,
    )?;
    validate_error_types(contract_interface)?;
    validate_enum_types(contract_interface)?;
    if !iroha_data_model::smart_contract::manifest::validate_contract_error_messages(
        &contract_interface.error_types,
        &contract_interface.error_messages,
    ) {
        return Err(ContractArtifactError::invalid(
            "CNTR error_messages must be sorted, unique, bounded text for declared error variants",
        ));
    }
    if profile == ValidationProfile::Production && contract_interface.entrypoints.is_empty() {
        return Err(ContractArtifactError::invalid(
            "CNTR must declare at least one entrypoint",
        ));
    }
    validate_bytecode_security(decoded, zk_enabled, profile)?;
    let valid_pcs = decoded.iter().map(|op| op.pc).collect::<BTreeSet<_>>();
    let mut entrypoint_names = BTreeSet::new();
    let mut entrypoint_kinds = BTreeMap::new();
    let mut entrypoint_pcs = BTreeSet::new();
    let mut entrypoint_reachability = BTreeMap::new();
    let mut hajimari_seen = false;
    let mut kaizen_seen = false;
    for entrypoint in &contract_interface.entrypoints {
        validate_entrypoint_name(&entrypoint.name)?;
        if !entrypoint_names.insert(entrypoint.name.clone()) {
            return Err(ContractArtifactError::invalid(format!(
                "duplicate entrypoint `{}`",
                entrypoint.name
            )));
        }
        entrypoint_kinds.insert(entrypoint.name.clone(), entrypoint.kind);
        if !valid_pcs.contains(&entrypoint.entry_pc) {
            return Err(ContractArtifactError::invalid(format!(
                "entrypoint `{}` has invalid entry_pc {}",
                entrypoint.name, entrypoint.entry_pc
            )));
        }
        if !entrypoint_pcs.insert(entrypoint.entry_pc) {
            return Err(ContractArtifactError::invalid(format!(
                "entrypoint `{}` reuses entry_pc {}",
                entrypoint.name, entrypoint.entry_pc
            )));
        }
        let reachability =
            reachable_syscalls(decoded, entrypoint.entry_pc, entrypoint.name.as_str())?;
        if profile == ValidationProfile::KotoTest
            && reachability
                .syscalls
                .iter()
                .any(|number| ivm_abi::syscalls::is_koto_test_syscall(*number))
        {
            return Err(ContractArtifactError::invalid(format!(
                "deployable entrypoint `{}` reaches a host-private Kotodama test syscall",
                entrypoint.name
            )));
        }
        match (&entrypoint.params[..], entrypoint.argument_schema.as_ref()) {
            ([], None) => {}
            ([], Some(_)) => {
                return Err(ContractArtifactError::invalid(format!(
                    "zero-parameter entrypoint `{}` must not declare an argument schema",
                    entrypoint.name
                )));
            }
            (params, Some(schema))
                if schema.validate()
                    && schema.fields.len() == params.len()
                    && schema.fields.iter().zip(params).all(|(field, param)| {
                        field.name == param.name
                            && field.ty.canonical_type_name().as_deref()
                                == Some(param.type_name.as_str())
                    }) => {}
            (_, Some(_)) => {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` has an invalid argument schema",
                    entrypoint.name
                )));
            }
            (_, None) => {
                return Err(ContractArtifactError::invalid(format!(
                    "parameterized entrypoint `{}` is missing its argument schema",
                    entrypoint.name
                )));
            }
        }
        match (
            entrypoint.return_type.as_deref(),
            entrypoint.return_schema.as_ref(),
        ) {
            (Some(type_name), Some(schema))
                if schema.validate()
                    && schema.canonical_type_name().as_deref() == Some(type_name)
                    && schema.word_count().is_some_and(|words| {
                        words <= ivm_abi::entrypoint::MAX_ENTRYPOINT_RETURN_WORDS
                    }) => {}
            (Some(_), Some(_)) => {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` has a return schema that does not match its declared type or exceeds the ABI v1 public schema or table bounds",
                    entrypoint.name
                )));
            }
            (Some(_), None) => {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` is missing its exact return schema",
                    entrypoint.name
                )));
            }
            (None, _) => {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` is missing its exact return descriptor; Unit requires type `()` and a Unit schema",
                    entrypoint.name
                )));
            }
        }
        if entrypoint.kind == EntryPointKind::View {
            validate_view_effects(&entrypoint.name, &reachability.syscalls)?;
        }
        if !entrypoint
            .authorization
            .is_valid_for(entrypoint.kind, &contract_interface.permissions)
        {
            return Err(ContractArtifactError::invalid(format!(
                "entrypoint `{}` must use explicit declared authorization; lifecycle hooks require RuntimeLifecycle",
                entrypoint.name
            )));
        }
        let canonical_lifecycle_kind = match entrypoint.name.as_str() {
            "hajimari" | "始まり" => Some(EntryPointKind::Hajimari),
            "kaizen" | "改善" => Some(EntryPointKind::Kaizen),
            _ => None,
        };
        match (entrypoint.kind, canonical_lifecycle_kind) {
            (EntryPointKind::Hajimari, Some(EntryPointKind::Hajimari))
            | (EntryPointKind::Kaizen, Some(EntryPointKind::Kaizen))
            | (EntryPointKind::Kotoage | EntryPointKind::View, None) => {}
            (EntryPointKind::Hajimari, _) => {
                return Err(ContractArtifactError::invalid(format!(
                    "hajimari/始まり entrypoint `{}` must use the reserved `hajimari` or `始まり` selector",
                    entrypoint.name
                )));
            }
            (EntryPointKind::Kaizen, _) => {
                return Err(ContractArtifactError::invalid(format!(
                    "kaizen/改善 entrypoint `{}` must use the reserved `kaizen` or `改善` selector",
                    entrypoint.name
                )));
            }
            (EntryPointKind::Kotoage | EntryPointKind::View, Some(_)) => {
                return Err(ContractArtifactError::invalid(format!(
                    "reserved hajimari/始まり or kaizen/改善 selector `{}` has the wrong entrypoint kind",
                    entrypoint.name
                )));
            }
        }
        validate_access_keys(&entrypoint.name, "read_keys", &entrypoint.read_keys)?;
        validate_access_keys(&entrypoint.name, "write_keys", &entrypoint.write_keys)?;
        for reason in &entrypoint.access_hints_skipped {
            if reason.trim().is_empty() {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` contains an empty access_hints_skipped reason",
                    entrypoint.name
                )));
            }
        }
        match entrypoint.access_hints_complete {
            Some(true) if !entrypoint.access_hints_skipped.is_empty() => {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` marks access hints complete but records skipped reasons",
                    entrypoint.name
                )));
            }
            Some(false) if entrypoint.access_hints_skipped.is_empty() => {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` marks access hints incomplete without a reason",
                    entrypoint.name
                )));
            }
            _ => {}
        }
        validate_entrypoint_access_claims(entrypoint, &reachability.syscalls)?;
        match entrypoint.kind {
            EntryPointKind::Hajimari if hajimari_seen => {
                return Err(ContractArtifactError::invalid(
                    "CNTR declares more than one hajimari entrypoint",
                ));
            }
            EntryPointKind::Hajimari => hajimari_seen = true,
            EntryPointKind::Kaizen if kaizen_seen => {
                return Err(ContractArtifactError::invalid(
                    "CNTR declares more than one kaizen entrypoint",
                ));
            }
            EntryPointKind::Kaizen => kaizen_seen = true,
            EntryPointKind::Kotoage | EntryPointKind::View => {}
        }
        entrypoint_reachability.insert(entrypoint.name.clone(), reachability);
    }
    let mut callable_roots = entrypoint_pcs.clone();
    if profile == ValidationProfile::KotoTest {
        // The crate-private loader authenticates this compiler-owned sidecar. Private test
        // functions are invocation roots without becoming public contract entrypoints.
        callable_roots.extend(
            contract_interface
                .callables
                .iter()
                .map(|callable| callable.entry_pc),
        );
    }
    validate_nonrecursive_direct_calls(decoded, &callable_roots)?;
    validate_callable_tables(contract_interface, decoded, &callable_roots, zk_enabled)?;
    // Entrypoint authorization is enforced by dispatch metadata, not by code at
    // the target PC. Shared implementation must live in private helpers.
    for caller in &contract_interface.entrypoints {
        let reachability = entrypoint_reachability
            .get(&caller.name)
            .expect("validated entrypoint reachability is retained");
        for target in &contract_interface.entrypoints {
            if caller.name != target.name && reachability.pcs.contains(&target.entry_pc) {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{}` reaches distinct entrypoint `{}` at pc {}; raw cross-entrypoint control flow bypasses dispatch authorization",
                    caller.name, target.name, target.entry_pc
                )));
            }
        }
    }
    let mut trigger_ids = BTreeSet::new();
    for entrypoint in &contract_interface.entrypoints {
        for trigger in &entrypoint.triggers {
            let trigger_id: &str = trigger.id.name().as_ref();
            if !is_canonical_source_declaration_name(trigger_id, false) {
                return Err(ContractArtifactError::invalid(format!(
                    "trigger ID `{trigger_id}` must be a canonical Kotodama V1 declaration identifier"
                )));
            }
            if !trigger_ids.insert(trigger.id.clone()) {
                return Err(ContractArtifactError::invalid(format!(
                    "duplicate trigger `{}`",
                    trigger.id
                )));
            }
            if let Some(namespace) = trigger.callback.namespace.as_deref()
                && !is_canonical_seiyaku_name(namespace)
            {
                return Err(ContractArtifactError::invalid(format!(
                    "trigger `{}` callback namespace `{namespace}` must be a canonical Kotodama V1 seiyaku identifier",
                    trigger.id
                )));
            }
            validate_entrypoint_name(&trigger.callback.entrypoint)?;
            if trigger.callback.namespace.is_none() {
                let Some(kind) = entrypoint_kinds.get(&trigger.callback.entrypoint) else {
                    return Err(ContractArtifactError::invalid(format!(
                        "trigger `{}` callback target `{}` is not a declared entrypoint",
                        trigger.id, trigger.callback.entrypoint
                    )));
                };
                if *kind != EntryPointKind::Kotoage {
                    return Err(ContractArtifactError::invalid(format!(
                        "trigger `{}` callback target `{}` must be a `kotoage`/`言挙げ` entrypoint",
                        trigger.id, trigger.callback.entrypoint
                    )));
                }
            }
        }
    }
    Ok(entrypoint_reachability
        .into_iter()
        .filter_map(|(name, reachability)| {
            reachability
                .syscalls
                .contains(&ivm_abi::syscalls::SYSCALL_GET_PRIVATE_INPUT)
                .then_some(name)
        })
        .collect())
}
fn is_canonical_source_identifier(name: &str) -> bool {
    iroha_data_model::smart_contract::entrypoint::is_canonical_kotodama_identifier(name)
}
fn is_canonical_source_declaration_name(name: &str, is_function: bool) -> bool {
    is_canonical_source_identifier(name)
        && !kotodama_surface::source_policy::is_reserved_source_declaration(name, is_function)
}
fn is_canonical_source_type_declaration_name(name: &str) -> bool {
    is_canonical_source_identifier(name)
        && !kotodama_surface::source_policy::is_reserved_source_type_declaration(name)
}
fn is_canonical_entrypoint_name(name: &str) -> bool {
    matches!(name, "hajimari" | "始まり" | "kaizen" | "改善")
        || is_canonical_source_declaration_name(name, true)
}
fn is_canonical_seiyaku_name(name: &str) -> bool {
    is_canonical_source_type_declaration_name(name)
}
fn validate_bytecode_security(
    decoded: &[DecodedOp],
    zk_enabled: bool,
    profile: ValidationProfile,
) -> Result<(), ContractArtifactError> {
    use ivm_abi::instruction::wide;
    let instruction_boundaries = decoded.iter().map(|op| op.pc).collect::<BTreeSet<_>>();
    for op in decoded {
        let opcode = wide::opcode(op.inst);
        if !wide::is_valid_opcode(opcode) {
            return Err(ContractArtifactError::invalid(format!(
                "invalid opcode 0x{opcode:02x} at pc {}",
                op.pc
            )));
        }
        if opcode == wide::crypto::POSEIDON6
            && ivm_abi::encoding::wide::decode_poseidon6(op.inst).is_none()
        {
            return Err(ContractArtifactError::invalid(format!(
                "noncanonical POSEIDON6 encoding at pc {}",
                op.pc
            )));
        }
        if opcode == wide::control::JR {
            return Err(ContractArtifactError::invalid(format!(
                "unverifiable indirect control flow at pc {}",
                op.pc
            )));
        }
        if opcode == wide::control::JALR {
            let (_, rd, base, immediate) = ivm_abi::encoding::wide::decode_rr(op.inst);
            if !(rd == 0 && base == 1 && immediate == 0) {
                return Err(ContractArtifactError::invalid(format!(
                    "unverifiable indirect control flow at pc {}",
                    op.pc
                )));
            }
        }
        if opcode == wide::control::JAL && !matches!(wide::rd(op.inst), 0 | 1) {
            return Err(ContractArtifactError::invalid(format!(
                "direct call at pc {} uses unsupported link register r{}",
                op.pc,
                wide::rd(op.inst)
            )));
        }
        let syscall = decoded_syscall_number(op.inst);
        if syscall.is_some_and(|syscall| {
            matches!(
                syscall,
                ivm_abi::syscalls::SYSCALL_GET_PRIVATE_INPUT
                    | ivm_abi::syscalls::SYSCALL_PRIVATE_NUMERIC_VALCOM
            )
        }) && !zk_enabled
        {
            return Err(ContractArtifactError::invalid(format!(
                "typed private-input syscall at pc {} requires ZK execution mode",
                op.pc
            )));
        }
        if let Some(number) = syscall
            && !profile.allows_syscall(number)
        {
            return Err(ContractArtifactError::invalid(format!(
                "disallowed syscall 0x{number:06x} at pc {}",
                op.pc
            )));
        }
        let offset_words = match opcode {
            wide::control::BEQ
            | wide::control::BNE
            | wide::control::BLT
            | wide::control::BGE
            | wide::control::BLTU
            | wide::control::BGEU => i64::from(wide::imm8(op.inst)),
            wide::control::JAL => i64::from(wide::imm16(op.inst)),
            wide::control::JMP | wide::control::JALS => i64::from(wide::imm24(op.inst)),
            _ => continue,
        };
        let Some(byte_offset) = offset_words.checked_mul(4) else {
            return Err(ContractArtifactError::invalid(format!(
                "control-flow offset overflows at pc {}",
                op.pc
            )));
        };
        let Some(target) = i128::from(op.pc)
            .checked_add(i128::from(byte_offset))
            .and_then(|target| u64::try_from(target).ok())
        else {
            return Err(ContractArtifactError::invalid(format!(
                "control-flow target is outside the executable stream at pc {}",
                op.pc
            )));
        };
        if !instruction_boundaries.contains(&target) {
            return Err(ContractArtifactError::invalid(format!(
                "control-flow target {target} from pc {} is not an instruction boundary",
                op.pc
            )));
        }
        let requires_fallthrough = matches!(
            opcode,
            wide::control::BEQ
                | wide::control::BNE
                | wide::control::BLT
                | wide::control::BGE
                | wide::control::BLTU
                | wide::control::BGEU
                | wide::control::JALS
        ) || (opcode == wide::control::JAL && wide::rd(op.inst) != 0);
        if requires_fallthrough {
            let fallthrough = op.pc.checked_add(4).ok_or_else(|| {
                ContractArtifactError::invalid(format!(
                    "control-flow fallthrough overflows at pc {}",
                    op.pc
                ))
            })?;
            if !instruction_boundaries.contains(&fallthrough) {
                return Err(ContractArtifactError::invalid(format!(
                    "control-flow fallthrough {fallthrough} from pc {} is not an instruction boundary",
                    op.pc
                )));
            }
        }
    }
    Ok(())
}
/// Bind the complete function graph to exact table roles and bounded stack reservations.
fn validate_callable_tables(
    interface: &EmbeddedContractInterfaceV1,
    decoded: &[DecodedOp],
    entrypoint_pcs: &BTreeSet<u64>,
    zk_enabled: bool,
) -> Result<(), ContractArtifactError> {
    let mut expected_roots = entrypoint_pcs.clone();
    for instruction in decoded
        .iter()
        .filter(|instruction| is_direct_call(instruction))
    {
        expected_roots.insert(direct_control_flow_target(instruction).ok_or_else(|| {
            ContractArtifactError::invalid(
                "callable table references an invalid direct-call target",
            )
        })?);
    }
    let mut declared_roots = BTreeSet::new();
    let mut previous = None;
    for callable in &interface.callables {
        if !callable.validate()
            || previous.is_some_and(|pc| callable.entry_pc <= pc)
            || (!zk_enabled
                && (callable.arguments.contains_private() || callable.results.contains_private()))
        {
            return Err(ContractArtifactError::invalid(
                "CNTR callables must have increasing unique roots, bounded aligned frames/tables, and valid role/privacy declarations",
            ));
        }
        previous = Some(callable.entry_pc);
        declared_roots.insert(callable.entry_pc);
    }
    if declared_roots != expected_roots {
        return Err(ContractArtifactError::invalid(
            "CNTR callable descriptors must cover exactly every entrypoint and direct-call root",
        ));
    }
    for entrypoint in &interface.entrypoints {
        let callable = interface
            .callables
            .binary_search_by_key(&entrypoint.entry_pc, |callable| callable.entry_pc)
            .ok()
            .and_then(|index| interface.callables.get(index))
            .ok_or_else(|| {
                ContractArtifactError::invalid("entrypoint has no callable descriptor")
            })?;
        let arguments_match = entrypoint
            .argument_schema
            .as_ref()
            .map_or(callable.arguments.nodes.is_empty(), |schema| {
                callable.arguments.matches_entrypoint_arguments(schema)
            });
        let results_match = entrypoint
            .return_schema
            .as_ref()
            .is_some_and(|schema| callable.results.matches_entrypoint_type(schema));
        if !arguments_match || !results_match {
            return Err(ContractArtifactError::invalid(format!(
                "entrypoint `{}` complete callable types do not match its canonical argument/result schemas",
                entrypoint.name
            )));
        }
    }
    Ok(())
}
fn decoded_syscall_number(instruction: u32) -> Option<u32> {
    use ivm_abi::instruction::wide;
    match wide::opcode(instruction) {
        wide::system::SCALL => Some(u32::from(wide::imm8(instruction).cast_unsigned())),
        wide::system::SYSTEM => Some(ivm_abi::encoding::wide::decode_syscallx(instruction)),
        _ => None,
    }
}
fn is_direct_call(op: &DecodedOp) -> bool {
    use ivm_abi::instruction::wide;
    let opcode = wide::opcode(op.inst);
    opcode == wide::control::JALS || (opcode == wide::control::JAL && wide::rd(op.inst) == 1)
}
/// A nominal failure cannot successfully return from its authenticated consumer.
/// The host either rejects it or synchronously halts with the complete error.
fn is_terminal_contract_abort(op: &DecodedOp) -> bool {
    decoded_syscall_number(op.inst) == Some(ivm_abi::syscalls::SYSCALL_CONTRACT_ABORT)
}
/// Prove the one finite nominal-abort suffix independently of compiler metadata.
/// Only its exact beginning may receive ordinary unconditional transfers; no
/// callable root, middle target, extra effect, return or substituted word is shared.
fn shared_nominal_abort_tail_pcs(
    decoded: &[DecodedOp],
    instructions: &BTreeMap<u64, &DecodedOp>,
    roots: &BTreeSet<u64>,
) -> BTreeSet<u64> {
    use ivm_abi::{encoding::wide as encoding, instruction::wide};
    if !decoded.iter().any(is_terminal_contract_abort) {
        return BTreeSet::new();
    }
    let ordinary_jump = |op: &DecodedOp| {
        wide::opcode(op.inst) == wide::control::JMP
            || (wide::opcode(op.inst) == wide::control::JAL && wide::rd(op.inst) == 0)
    };
    // One target census covers all decoded edges, including unreachable words.
    // False records any incoming edge that could call or conditionally enter.
    let mut incoming = BTreeMap::<u64, bool>::new();
    for op in decoded {
        if let Some(target) = direct_control_flow_target(op) {
            incoming
                .entry(target)
                .and_modify(|allowed| *allowed &= ordinary_jump(op))
                .or_insert_with(|| ordinary_jump(op));
        }
    }
    let (Ok(publish), Ok(abort)) = (
        u8::try_from(ivm_abi::syscalls::SYSCALL_INPUT_PUBLISH_TLV),
        u8::try_from(ivm_abi::syscalls::SYSCALL_CONTRACT_ABORT),
    ) else {
        // This exact suffix requires the short SCALL encoding.
        return BTreeSet::new();
    };
    let expected = [
        encoding::encode_sys(wide::system::SCALL, publish),
        encoding::encode_rr(wide::arithmetic::ADDI, 12, 0, 0),
        encoding::encode_rr(wide::arithmetic::ADDI, 13, 0, 0),
        encoding::encode_rr(wide::arithmetic::ADDI, 14, 0, 0),
        encoding::encode_rr(wide::arithmetic::ADDI, 15, 0, 0),
        encoding::encode_sys(wide::system::SCALL, abort),
    ];
    let mut proven = BTreeSet::new();
    for suffix in decoded.windows(expected.len()) {
        let start = suffix[0].pc;
        if incoming.get(&start) != Some(&true)
            || suffix.iter().enumerate().any(|(index, op)| {
                op.inst != expected[index]
                    || start.checked_add((index as u64) * 4) != Some(op.pc)
                    || roots.contains(&op.pc)
                    || (index != 0 && incoming.contains_key(&op.pc))
            })
        {
            continue;
        }
        let Some(previous) = start.checked_sub(4).and_then(|pc| instructions.get(&pc)) else {
            continue;
        };
        if !matches!(
            wide::opcode(previous.inst),
            wide::control::HALT | wide::control::JALR
        ) && !ordinary_jump(previous)
            && !is_terminal_contract_abort(previous)
        {
            // A normal path must not fall through into the borrowed failure body.
            continue;
        }
        proven.extend(suffix.iter().map(|op| op.pc));
    }
    proven
}
/// Validate the deployable direct-call graph without trusting compiler metadata.
fn validate_nonrecursive_direct_calls(
    decoded: &[DecodedOp],
    entrypoint_pcs: &BTreeSet<u64>,
) -> Result<(), ContractArtifactError> {
    use ivm_abi::instruction::wide;
    let instructions = decoded
        .iter()
        .map(|op| (op.pc, op))
        .collect::<BTreeMap<_, _>>();
    let mut roots = entrypoint_pcs.clone();
    for op in decoded.iter().filter(|op| is_direct_call(op)) {
        let target = direct_control_flow_target(op).ok_or_else(|| {
            ContractArtifactError::invalid(format!(
                "direct call at pc {} has an invalid target",
                op.pc
            ))
        })?;
        roots.insert(target);
    }
    let terminal_tail_pcs = shared_nominal_abort_tail_pcs(decoded, &instructions, &roots);
    let mut owners = BTreeMap::<u64, u64>::new();
    let mut pending = roots
        .iter()
        .copied()
        .map(|root| (root, root))
        .collect::<VecDeque<_>>();
    while let Some((pc, owner)) = pending.pop_front() {
        if let Some(previous) = owners.get(&pc).copied() {
            if previous != owner && !terminal_tail_pcs.contains(&pc) {
                return Err(ContractArtifactError::invalid(format!(
                    "ordinary control flow at pc {pc} is shared by function roots {previous} and {owner}; helper entry requires a direct call"
                )));
            }
            continue;
        }
        owners.insert(pc, owner);
        let op = instructions.get(&pc).ok_or_else(|| {
            ContractArtifactError::invalid(format!(
                "function root {owner} reaches non-instruction pc {pc}"
            ))
        })?;
        if is_terminal_contract_abort(op) {
            continue;
        }
        let opcode = wide::opcode(op.inst);
        let fallthrough = || {
            op.pc.checked_add(4).ok_or_else(|| {
                ContractArtifactError::invalid(format!(
                    "control-flow fallthrough overflows at pc {}",
                    op.pc
                ))
            })
        };
        let target = || {
            direct_control_flow_target(op).ok_or_else(|| {
                ContractArtifactError::invalid(format!(
                    "control-flow instruction at pc {} has an invalid target",
                    op.pc
                ))
            })
        };
        match opcode {
            wide::control::HALT | wide::control::JALR => {}
            wide::control::BEQ
            | wide::control::BNE
            | wide::control::BLT
            | wide::control::BGE
            | wide::control::BLTU
            | wide::control::BGEU => {
                pending.push_back((target()?, owner));
                pending.push_back((fallthrough()?, owner));
            }
            wide::control::JAL if wide::rd(op.inst) == 0 => {
                pending.push_back((target()?, owner));
            }
            wide::control::JMP => pending.push_back((target()?, owner)),
            wide::control::JAL | wide::control::JALS => {
                pending.push_back((fallthrough()?, owner));
            }
            wide::control::JR => {
                return Err(ContractArtifactError::invalid(format!(
                    "unverifiable indirect control flow at pc {}",
                    op.pc
                )));
            }
            _ => pending.push_back((fallthrough()?, owner)),
        }
    }
    let mut calls = roots
        .iter()
        .copied()
        .map(|root| (root, BTreeSet::<u64>::new()))
        .collect::<BTreeMap<_, _>>();
    for op in decoded.iter().filter(|op| is_direct_call(op)) {
        let Some(owner) = owners.get(&op.pc).copied() else {
            return Err(ContractArtifactError::invalid(format!(
                "direct call at pc {} is unreachable from every entrypoint or helper root",
                op.pc
            )));
        };
        let target = direct_control_flow_target(op).expect("validated direct-call target");
        calls
            .get_mut(&owner)
            .expect("every control-flow owner is a function root")
            .insert(target);
    }
    let mut indegree = roots
        .iter()
        .copied()
        .map(|root| (root, 0usize))
        .collect::<BTreeMap<_, _>>();
    for targets in calls.values() {
        for target in targets {
            let degree = indegree
                .get_mut(target)
                .expect("every direct-call target is a function root");
            *degree = degree.checked_add(1).ok_or_else(|| {
                ContractArtifactError::invalid("direct-call graph indegree overflow")
            })?;
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(root, degree)| (*degree == 0).then_some(*root))
        .collect::<VecDeque<_>>();
    let mut visited = 0usize;
    while let Some(root) = ready.pop_front() {
        visited += 1;
        for target in calls
            .get(&root)
            .expect("every function root has a call-graph node")
        {
            let degree = indegree
                .get_mut(target)
                .expect("every direct-call target has an indegree");
            *degree -= 1;
            if *degree == 0 {
                ready.push_back(*target);
            }
        }
    }
    if visited != roots.len() {
        let cycle_pc = indegree
            .iter()
            .find_map(|(root, degree)| (*degree != 0).then_some(*root))
            .expect("a partially visited finite graph retains a cycle node");
        return Err(ContractArtifactError::invalid(format!(
            "recursive direct-call cycle reaches function root pc {cycle_pc}; recursion is forbidden in Kotodama V1"
        )));
    }
    Ok(())
}
fn direct_control_flow_target(op: &DecodedOp) -> Option<u64> {
    use ivm_abi::instruction::wide;
    let offset_words = match wide::opcode(op.inst) {
        wide::control::BEQ
        | wide::control::BNE
        | wide::control::BLT
        | wide::control::BGE
        | wide::control::BLTU
        | wide::control::BGEU => i64::from(wide::imm8(op.inst)),
        wide::control::JAL => i64::from(wide::imm16(op.inst)),
        wide::control::JMP | wide::control::JALS => i64::from(wide::imm24(op.inst)),
        _ => return None,
    };
    let byte_offset = offset_words.checked_mul(4)?;
    i128::from(op.pc)
        .checked_add(i128::from(byte_offset))
        .and_then(|target| u64::try_from(target).ok())
}
struct Reachability {
    syscalls: BTreeSet<u32>,
    pcs: BTreeSet<u64>,
}
fn reachable_syscalls(
    decoded: &[DecodedOp],
    entry_pc: u64,
    entrypoint_name: &str,
) -> Result<Reachability, ContractArtifactError> {
    use ivm_abi::instruction::wide;
    let instructions = decoded
        .iter()
        .map(|op| (op.pc, op))
        .collect::<BTreeMap<_, _>>();
    let mut pending = VecDeque::from([entry_pc]);
    let mut visited = BTreeSet::new();
    let mut syscalls = BTreeSet::new();
    while let Some(pc) = pending.pop_front() {
        if !visited.insert(pc) {
            continue;
        }
        let op = instructions.get(&pc).ok_or_else(|| {
            ContractArtifactError::invalid(format!(
                "entrypoint `{entrypoint_name}` reaches non-instruction pc {pc}"
            ))
        })?;
        if let Some(number) = decoded_syscall_number(op.inst) {
            syscalls.insert(number);
        }
        if is_terminal_contract_abort(op) {
            continue;
        }
        let opcode = wide::opcode(op.inst);
        let fallthrough = op.pc.checked_add(4);
        match opcode {
            wide::control::HALT => {}
            wide::control::BEQ
            | wide::control::BNE
            | wide::control::BLT
            | wide::control::BGE
            | wide::control::BLTU
            | wide::control::BGEU => {
                pending.push_back(direct_control_flow_target(op).ok_or_else(|| {
                    ContractArtifactError::invalid(format!(
                        "entrypoint `{entrypoint_name}` has an invalid branch at pc {}",
                        op.pc
                    ))
                })?);
                pending.push_back(fallthrough.ok_or_else(|| {
                    ContractArtifactError::invalid("control-flow fallthrough overflows")
                })?);
            }
            wide::control::JAL => {
                pending.push_back(direct_control_flow_target(op).ok_or_else(|| {
                    ContractArtifactError::invalid(format!(
                        "entrypoint `{entrypoint_name}` has an invalid jump at pc {}",
                        op.pc
                    ))
                })?);
                if wide::rd(op.inst) != 0 {
                    pending.push_back(fallthrough.ok_or_else(|| {
                        ContractArtifactError::invalid("call fallthrough overflows")
                    })?);
                }
            }
            wide::control::JMP => {
                pending.push_back(direct_control_flow_target(op).ok_or_else(|| {
                    ContractArtifactError::invalid(format!(
                        "entrypoint `{entrypoint_name}` has an invalid jump at pc {}",
                        op.pc
                    ))
                })?);
            }
            wide::control::JALS => {
                pending.push_back(direct_control_flow_target(op).ok_or_else(|| {
                    ContractArtifactError::invalid(format!(
                        "entrypoint `{entrypoint_name}` has an invalid call at pc {}",
                        op.pc
                    ))
                })?);
                pending.push_back(
                    fallthrough.ok_or_else(|| {
                        ContractArtifactError::invalid("call fallthrough overflows")
                    })?,
                );
            }
            wide::control::JALR => {
                let (_, rd, base, immediate) = ivm_abi::encoding::wide::decode_rr(op.inst);
                if !(rd == 0 && base == 1 && immediate == 0) {
                    return Err(ContractArtifactError::invalid(format!(
                        "entrypoint `{entrypoint_name}` reaches unverifiable indirect control flow at pc {}",
                        op.pc
                    )));
                }
            }
            wide::control::JR => {
                return Err(ContractArtifactError::invalid(format!(
                    "entrypoint `{entrypoint_name}` reaches unverifiable indirect control flow at pc {}",
                    op.pc
                )));
            }
            _ => {
                pending.push_back(fallthrough.ok_or_else(|| {
                    ContractArtifactError::invalid("control-flow fallthrough overflows")
                })?);
            }
        }
    }
    Ok(Reachability {
        syscalls,
        pcs: visited,
    })
}
fn validate_view_effects(
    entrypoint_name: &str,
    syscalls: &BTreeSet<u32>,
) -> Result<(), ContractArtifactError> {
    for number in syscalls {
        // A typed call authenticates its exact target at runtime. View hosts reject
        // a non-view target before copying arguments or executing child effects.
        if *number == ivm_abi::syscalls::SYSCALL_CALL_CONTRACT {
            continue;
        }
        if matches!(
            ivm_abi::syscalls::syscall_access(*number),
            ivm_abi::syscalls::SyscallAccess::StateWrite
                | ivm_abi::syscalls::SyscallAccess::LedgerWrite
                | ivm_abi::syscalls::SyscallAccess::Dynamic
        ) {
            return Err(ContractArtifactError::invalid(format!(
                "view entrypoint `{entrypoint_name}` transitively reaches effectful syscall 0x{number:06x}"
            )));
        }
    }
    Ok(())
}
fn validate_entrypoint_access_claims(
    entrypoint: &EmbeddedEntrypointDescriptor,
    syscalls: &BTreeSet<u32>,
) -> Result<(), ContractArtifactError> {
    if entrypoint.access_hints_complete != Some(true) {
        return Ok(());
    }
    for number in syscalls {
        let access = ivm_abi::syscalls::syscall_access(*number);
        let covers_access = if *number == ivm_abi::syscalls::SYSCALL_CALL_CONTRACT
            && entrypoint.kind == EntryPointKind::View
        {
            // A dynamically addressed view can read any state or ledger key.
            // A particular ledger read hint cannot cover this boundary.
            entrypoint
                .read_keys
                .iter()
                .chain(&entrypoint.write_keys)
                .any(|key| key == "*")
        } else {
            entrypoint_claim_covers_access(entrypoint, access)
        };
        if !covers_access {
            return Err(ContractArtifactError::invalid(format!(
                "entrypoint `{}` marks access hints complete but under-reports transitively reachable {access:?} syscall 0x{number:06x}",
                entrypoint.name
            )));
        }
    }
    Ok(())
}
fn entrypoint_claim_covers_access(
    entrypoint: &EmbeddedEntrypointDescriptor,
    access: ivm_abi::syscalls::SyscallAccess,
) -> bool {
    use ivm_abi::syscalls::SyscallAccess;
    let is_state_key = |key: &str| key.starts_with("state:");
    let global_read = entrypoint.read_keys.iter().any(|key| key == "*")
        || entrypoint.write_keys.iter().any(|key| key == "*");
    let global_write = entrypoint.write_keys.iter().any(|key| key == "*");
    let state_read = entrypoint.read_keys.iter().any(|key| is_state_key(key))
        || entrypoint.write_keys.iter().any(|key| is_state_key(key));
    let state_write = entrypoint.write_keys.iter().any(|key| is_state_key(key));
    let ledger_read = entrypoint
        .read_keys
        .iter()
        .chain(&entrypoint.write_keys)
        .any(|key| key != "*" && !is_state_key(key));
    let ledger_write = entrypoint
        .write_keys
        .iter()
        .any(|key| key != "*" && !is_state_key(key));
    match access {
        SyscallAccess::None => true,
        SyscallAccess::StateRead => global_read || state_read,
        SyscallAccess::StateWrite => global_write || state_write,
        SyscallAccess::LedgerRead => global_read || ledger_read,
        SyscallAccess::LedgerWrite => global_write || ledger_write,
        SyscallAccess::Dynamic => global_write,
    }
}
fn validate_access_set_hints(
    access_set_hints: Option<&AccessSetHints>,
) -> Result<(), ContractArtifactError> {
    let Some(access_set_hints) = access_set_hints else {
        return Ok(());
    };
    validate_access_keys(
        "contract",
        "access_set_hints.read_keys",
        &access_set_hints.read_keys,
    )?;
    validate_access_keys(
        "contract",
        "access_set_hints.write_keys",
        &access_set_hints.write_keys,
    )?;
    validate_dynamic_access_hints(
        "contract",
        "access_set_hints.dynamic_reads",
        &access_set_hints.dynamic_reads,
    )?;
    validate_dynamic_access_hints(
        "contract",
        "access_set_hints.dynamic_writes",
        &access_set_hints.dynamic_writes,
    )?;
    Ok(())
}
fn validate_access_keys(
    owner: &str,
    field: &str,
    keys: &[String],
) -> Result<(), ContractArtifactError> {
    for key in keys {
        if key.trim().is_empty() {
            return Err(ContractArtifactError::invalid(format!(
                "{owner} contains an empty {field} entry"
            )));
        }
    }
    Ok(())
}
fn validate_dynamic_access_hints(
    owner: &str,
    field: &str,
    hints: &[DynamicAccessHint],
) -> Result<(), ContractArtifactError> {
    let mut unique = BTreeSet::new();
    for hint in hints {
        if !unique.insert(hint) {
            return Err(ContractArtifactError::invalid(format!(
                "{owner} contains duplicate {field} hint `{}`",
                hint.base_key
            )));
        }
        ivm_abi::access_hints::validate_dynamic_access_hint_v1(hint).map_err(|error| {
            ContractArtifactError::invalid(format!(
                "{owner} contains invalid {field} hint `{}`: {error}",
                hint.base_key
            ))
        })?;
    }
    Ok(())
}
fn embedded_state_map_key_type_name(ty: &EmbeddedStateType) -> Option<String> {
    ivm_abi::state_value::state_map_key_schema_v1(ty)
        .ok()?
        .canonical_type_name()
}

fn validate_dynamic_access_hint_state_maps(
    access_set_hints: Option<&AccessSetHints>,
    states: &[EmbeddedStateDescriptor],
) -> Result<(), ContractArtifactError> {
    let Some(access_set_hints) = access_set_hints else {
        return Ok(());
    };
    let state_maps = states
        .iter()
        .filter_map(|state| {
            let EmbeddedStateType::StateMap { key, .. } = &state.ty else {
                return None;
            };
            embedded_state_map_key_type_name(key).map(|key_type| (state.name.as_str(), key_type))
        })
        .collect::<BTreeMap<_, _>>();
    for (field, hints) in [
        (
            "access_set_hints.dynamic_reads",
            access_set_hints.dynamic_reads.as_slice(),
        ),
        (
            "access_set_hints.dynamic_writes",
            access_set_hints.dynamic_writes.as_slice(),
        ),
    ] {
        for hint in hints {
            let state_name = ivm_abi::access_hints::dynamic_access_hint_state_name_v1(
                &hint.base_key,
            )
            .map_err(|error| {
                ContractArtifactError::invalid(format!(
                    "contract contains invalid {field} hint `{}`: {error}",
                    hint.base_key
                ))
            })?;
            let Some(expected_key_type) = state_maps.get(state_name) else {
                return Err(ContractArtifactError::invalid(format!(
                    "contract {field} hint `{}` must reference a declared top-level StateMap",
                    hint.base_key
                )));
            };
            if hint.key_type != *expected_key_type {
                return Err(ContractArtifactError::invalid(format!(
                    "contract {field} hint `{}` declares key_type `{}` but its StateMap key type is `{expected_key_type}`",
                    hint.base_key, hint.key_type
                )));
            }
        }
    }
    Ok(())
}
fn validate_kotoba_entries(
    entries: &[KotobaTranslationEntry],
) -> Result<(), ContractArtifactError> {
    let mut msg_ids = BTreeSet::new();
    for entry in entries {
        if entry.msg_id.trim().is_empty() {
            return Err(ContractArtifactError::invalid(
                "CNTR kotoba entries must not contain an empty msg_id",
            ));
        }
        if !msg_ids.insert(entry.msg_id.clone()) {
            return Err(ContractArtifactError::invalid(format!(
                "duplicate kotoba msg_id `{}`",
                entry.msg_id
            )));
        }
        let mut langs = BTreeSet::new();
        for translation in &entry.translations {
            if translation.lang.trim().is_empty() {
                return Err(ContractArtifactError::invalid(format!(
                    "kotoba entry `{}` contains an empty language tag",
                    entry.msg_id
                )));
            }
            if !langs.insert(translation.lang.clone()) {
                return Err(ContractArtifactError::invalid(format!(
                    "kotoba entry `{}` declares duplicate language `{}`",
                    entry.msg_id, translation.lang
                )));
            }
        }
    }
    Ok(())
}
fn validate_entrypoint_name(name: &str) -> Result<(), ContractArtifactError> {
    if name.is_empty() {
        return Err(ContractArtifactError::invalid(
            "entrypoint names must not be empty",
        ));
    }
    if !is_canonical_entrypoint_name(name) {
        return Err(ContractArtifactError::invalid(format!(
            "entrypoint `{name}` is not a canonical Kotodama V1 identifier or branded lifecycle selector"
        )));
    }
    Ok(())
}
fn validate_state_descriptors(
    contract_interface: &EmbeddedContractInterfaceV1,
) -> Result<(), ContractArtifactError> {
    let mut names = BTreeSet::new();
    for state in &contract_interface.states {
        if state.name.trim().is_empty() {
            return Err(ContractArtifactError::invalid(
                "CNTR state descriptors must not use an empty name",
            ));
        }
        if !is_canonical_source_declaration_name(&state.name, false) {
            return Err(ContractArtifactError::invalid(format!(
                "state descriptor `{}` is not a canonical Kotodama V1 identifier",
                state.name
            )));
        }
        if !names.insert(state.name.clone()) {
            return Err(ContractArtifactError::invalid(format!(
                "duplicate state descriptor `{}`",
                state.name
            )));
        }
        validate_state_type(&state.ty, true)?;
        validate_runtime_state_schema(&state.name, &state.ty)?;
    }
    Ok(())
}
fn validate_runtime_state_schema(
    state_name: &str,
    declared_type: &EmbeddedStateType,
) -> Result<(), ContractArtifactError> {
    let runtime_value_type = match declared_type {
        EmbeddedStateType::StateMap { value, .. } => value.as_ref(),
        ty => ty,
    };
    if admissible_state_value_schema_for_embedded_type_v1(runtime_value_type).is_none() {
        return Err(ContractArtifactError::invalid(format!(
            "CNTR state descriptor `{state_name}` exceeds the exact V1 runtime StateValueSchema limit of {MAX_STATE_VALUE_NODES} nodes or levels and {MAX_STATE_VALUE_SCHEMA_BYTES} encoded bytes"
        )));
    }
    Ok(())
}
fn validate_error_types(
    contract_interface: &EmbeddedContractInterfaceV1,
) -> Result<(), ContractArtifactError> {
    use iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1;
    let catalog = &contract_interface.error_types;
    if catalog.len() > 256 {
        return Err(ContractArtifactError::invalid(
            "CNTR exceeds 256 nominal error types",
        ));
    }
    let mut identities = BTreeSet::new();
    for error in catalog {
        if !error.validate() || !identities.insert(&error.identity) {
            return Err(ContractArtifactError::invalid(
                "invalid or duplicate nominal error descriptor",
            ));
        }
    }
    let require_declared =
        |error: &iroha_data_model::smart_contract::manifest::ContractErrorTypeDescriptor| {
            if catalog.contains(error) {
                Ok(())
            } else {
                Err(ContractArtifactError::invalid(
                    "schema error type does not exactly match a CNTR error descriptor",
                ))
            }
        };
    for entrypoint in &contract_interface.entrypoints {
        for schema in entrypoint
            .argument_schema
            .iter()
            .flat_map(|schema| schema.fields.iter().map(|field| &field.ty))
            .chain(entrypoint.return_schema.iter())
        {
            for node in &schema.nodes {
                if let EntrypointValueTypeNodeV1::Error(error) = node {
                    require_declared(error)?;
                }
            }
        }
    }
    for event in &contract_interface.events {
        for node in &event.payload_type.nodes {
            if let EntrypointValueTypeNodeV1::Error(error) = node {
                require_declared(error)?;
            }
        }
    }
    for callable in &contract_interface.callables {
        for node in callable
            .arguments
            .nodes
            .iter()
            .chain(&callable.results.nodes)
        {
            if let ivm_abi::call::CallTypeNodeV1::Error(error) = node {
                require_declared(error)?;
            }
        }
    }
    let mut pending = contract_interface
        .states
        .iter()
        .map(|state| &state.ty)
        .collect::<Vec<_>>();
    while let Some(ty) = pending.pop() {
        match ty {
            EmbeddedStateType::Error(error) => require_declared(error)?,
            EmbeddedStateType::Tuple(items) => pending.extend(items),
            EmbeddedStateType::Struct { fields, .. } => {
                pending.extend(fields.iter().map(|field| &field.ty))
            }
            EmbeddedStateType::StateMap { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            EmbeddedStateType::Result { ok, err } => {
                pending.push(ok);
                pending.push(err);
            }
            EmbeddedStateType::Option(value) | EmbeddedStateType::List { element: value, .. } => {
                pending.push(value)
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_enum_types(
    contract_interface: &EmbeddedContractInterfaceV1,
) -> Result<(), ContractArtifactError> {
    use iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1;
    let catalog = &contract_interface.enum_types;
    if !iroha_data_model::smart_contract::manifest::validate_contract_enum_table(catalog) {
        return Err(ContractArtifactError::invalid(
            "CNTR enum_types must be sorted unique canonical descriptors within the 256-type and 64-KiB limits",
        ));
    }
    if catalog.iter().any(|enumeration| {
        contract_interface
            .error_types
            .iter()
            .any(|error| error.identity == enumeration.identity)
    }) {
        return Err(ContractArtifactError::invalid(
            "CNTR ordinary enum and error identities must not overlap",
        ));
    }
    let require_declared =
        |descriptor: &iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1| {
            if catalog.contains(descriptor) {
                Ok(())
            } else {
                Err(ContractArtifactError::invalid(
                    "ordinary enum schema does not exactly match a CNTR ordinary enum descriptor",
                ))
            }
        };
    for entrypoint in &contract_interface.entrypoints {
        for schema in entrypoint
            .argument_schema
            .iter()
            .flat_map(|schema| schema.fields.iter().map(|field| &field.ty))
            .chain(entrypoint.return_schema.iter())
        {
            for node in &schema.nodes {
                if let EntrypointValueTypeNodeV1::Enum(descriptor) = node {
                    require_declared(descriptor)?;
                }
            }
        }
    }
    for event in &contract_interface.events {
        for node in &event.payload_type.nodes {
            if let EntrypointValueTypeNodeV1::Enum(descriptor) = node {
                require_declared(descriptor)?;
            }
        }
    }
    for callable in &contract_interface.callables {
        for node in callable
            .arguments
            .nodes
            .iter()
            .chain(&callable.results.nodes)
        {
            if let ivm_abi::call::CallTypeNodeV1::Enum(descriptor) = node {
                require_declared(descriptor)?;
            }
        }
    }
    let mut pending = contract_interface
        .states
        .iter()
        .map(|state| &state.ty)
        .collect::<Vec<_>>();
    while let Some(ty) = pending.pop() {
        match ty {
            EmbeddedStateType::Enum(descriptor) => require_declared(descriptor)?,
            EmbeddedStateType::Tuple(items) => pending.extend(items),
            EmbeddedStateType::Struct { fields, .. } => {
                pending.extend(fields.iter().map(|field| &field.ty))
            }
            EmbeddedStateType::StateMap { key, value } => {
                pending.push(key);
                pending.push(value);
            }
            EmbeddedStateType::Result { ok, err } => {
                pending.push(ok);
                pending.push(err);
            }
            EmbeddedStateType::Option(value) | EmbeddedStateType::List { element: value, .. } => {
                pending.push(value)
            }
            _ => {}
        }
    }
    Ok(())
}

fn is_supported_state_map_key(ty: &EmbeddedStateType) -> bool {
    ivm_abi::state_value::state_map_key_schema_v1(ty).is_ok()
}

enum PendingStateTypeValidation<'a> {
    Type {
        ty: &'a EmbeddedStateType,
        allow_state_map: bool,
    },
    StructFields {
        struct_name: &'a str,
        fields: &'a [ivm_abi::metadata::EmbeddedStateFieldDescriptor],
        index: usize,
        field_names: BTreeSet<&'a str>,
    },
}
fn validate_state_type(
    ty: &EmbeddedStateType,
    allow_state_map: bool,
) -> Result<(), ContractArtifactError> {
    let mut pending = vec![PendingStateTypeValidation::Type {
        ty,
        allow_state_map,
    }];
    while let Some(item) = pending.pop() {
        validate_pending_state_type(item, &mut pending)?;
    }
    Ok(())
}
fn validate_pending_state_type<'a>(
    item: PendingStateTypeValidation<'a>,
    pending: &mut Vec<PendingStateTypeValidation<'a>>,
) -> Result<(), ContractArtifactError> {
    match item {
        PendingStateTypeValidation::StructFields {
            struct_name,
            fields,
            index,
            field_names,
        } => validate_pending_struct_fields(struct_name, fields, index, field_names, pending),
        PendingStateTypeValidation::Type {
            ty,
            allow_state_map,
        } => schedule_nested_state_types(ty, allow_state_map, pending),
    }
}
fn validate_pending_struct_fields<'a>(
    struct_name: &'a str,
    fields: &'a [ivm_abi::metadata::EmbeddedStateFieldDescriptor],
    index: usize,
    mut field_names: BTreeSet<&'a str>,
    pending: &mut Vec<PendingStateTypeValidation<'a>>,
) -> Result<(), ContractArtifactError> {
    let Some(field) = fields.get(index) else {
        return Ok(());
    };
    if !is_canonical_source_identifier(&field.name) {
        return Err(ContractArtifactError::invalid(format!(
            "CNTR struct `{struct_name}` contains noncanonical field `{}`",
            field.name
        )));
    }
    if !field_names.insert(field.name.as_str()) {
        return Err(ContractArtifactError::invalid(format!(
            "CNTR struct `{struct_name}` contains duplicate field `{}`",
            field.name
        )));
    }
    pending.push(PendingStateTypeValidation::StructFields {
        struct_name,
        fields,
        index: index + 1,
        field_names,
    });
    pending.push(PendingStateTypeValidation::Type {
        ty: &field.ty,
        allow_state_map: false,
    });
    Ok(())
}
fn schedule_nested_state_types<'a>(
    ty: &'a EmbeddedStateType,
    allow_state_map: bool,
    pending: &mut Vec<PendingStateTypeValidation<'a>>,
) -> Result<(), ContractArtifactError> {
    match ty {
        EmbeddedStateType::StateCursor(key) => {
            let schema = iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::StateCursor(key.clone())],
            };
            if !schema.validate() {
                return Err(ContractArtifactError::invalid(
                    "CNTR StateCursor key must be a bounded canonical scalar or tuple schema",
                ));
            }
        }
        EmbeddedStateType::Tuple(items) => {
            if items.len() < 2 {
                return Err(ContractArtifactError::invalid(
                    "CNTR durable tuples require at least two elements",
                ));
            }
            pending.extend(
                items
                    .iter()
                    .rev()
                    .map(|item| PendingStateTypeValidation::Type {
                        ty: item,
                        allow_state_map: false,
                    }),
            );
        }
        EmbeddedStateType::Struct { name, fields } => {
            let valid_name =
                iroha_data_model::smart_contract::entrypoint::is_canonical_kotodama_struct_name(
                    name,
                );
            if !valid_name {
                return Err(ContractArtifactError::invalid(format!(
                    "CNTR struct `{name}` is not a canonical Kotodama V1 struct identity"
                )));
            }
            pending.push(PendingStateTypeValidation::StructFields {
                struct_name: name,
                fields,
                index: 0,
                field_names: BTreeSet::new(),
            });
        }
        EmbeddedStateType::StateMap { key, value } => {
            if !allow_state_map {
                return Err(ContractArtifactError::invalid(
                    "CNTR StateMap is a top-level durable collection and cannot be nested",
                ));
            }
            if !is_supported_state_map_key(key) {
                return Err(ContractArtifactError::invalid(
                    "CNTR StateMap key must be a bounded canonical scalar or tuple key schema",
                ));
            }
            pending.push(PendingStateTypeValidation::Type {
                ty: value,
                allow_state_map: false,
            });
        }
        EmbeddedStateType::Option(value) => pending.push(PendingStateTypeValidation::Type {
            ty: value,
            allow_state_map: false,
        }),
        EmbeddedStateType::Result { ok, err } => {
            pending.push(PendingStateTypeValidation::Type {
                ty: err,
                allow_state_map: false,
            });
            pending.push(PendingStateTypeValidation::Type {
                ty: ok,
                allow_state_map: false,
            });
        }
        EmbeddedStateType::List { element, capacity } => {
            if !(1..=64).contains(capacity) {
                return Err(ContractArtifactError::invalid(
                    "CNTR List capacity must be in 1..=64",
                ));
            }
            pending.push(PendingStateTypeValidation::Type {
                ty: element,
                allow_state_map: false,
            });
        }
        _ => {}
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_view_calls_require_global_reads_and_keep_other_effects_forbidden() {
        use ivm_abi::syscalls::{self, SyscallAccess};
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                "seiyaku ViewCalls { view fn inspect() authorize(anyone) -> int { 1 } }",
            )
            .expect("compile a canonical view descriptor");
        let mut entrypoint = ProgramMetadata::parse(&artifact)
            .unwrap()
            .contract_interface
            .unwrap()
            .entrypoints
            .remove(0);
        entrypoint.access_hints_complete = Some(true);
        entrypoint.read_keys = vec!["*".into()];
        entrypoint.write_keys.clear();
        let calls = BTreeSet::from([syscalls::SYSCALL_CALL_CONTRACT]);
        validate_view_effects(&entrypoint.name, &calls)
            .expect("the host authenticates the target's view class");
        validate_entrypoint_access_claims(&entrypoint, &calls)
            .expect("global reads cover a dynamically addressed view");
        for reads in [
            vec![],
            vec!["state:counter".into()],
            vec!["account:alice".into()],
        ] {
            entrypoint.read_keys = reads;
            validate_entrypoint_access_claims(&entrypoint, &calls)
                .expect_err("a dynamic view cannot claim a particular key or no reads");
        }
        entrypoint.read_keys = vec!["*".into()];
        entrypoint.kind = EntryPointKind::Kotoage;
        validate_entrypoint_access_claims(&entrypoint, &calls)
            .expect_err("a mutating caller still needs global writes");
        entrypoint.write_keys = vec!["*".into()];
        validate_entrypoint_access_claims(&entrypoint, &calls).unwrap();
        for number in syscalls::abi_syscall_list()
            .iter()
            .copied()
            .filter(|number| {
                *number != syscalls::SYSCALL_CALL_CONTRACT
                    && matches!(
                        syscalls::syscall_access(*number),
                        SyscallAccess::StateWrite
                            | SyscallAccess::LedgerWrite
                            | SyscallAccess::Dynamic
                    )
            })
        {
            validate_view_effects("inspect", &BTreeSet::from([number]))
                .expect_err("the typed-call exception cannot admit any other effect");
        }
    }
    #[test]
    fn ordinary_enum_inventory_binds_every_schema_and_never_aliases_error_types() {
        use iroha_data_model::smart_contract::{
            entrypoint::{
                EntrypointStructTypeNodeV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
            },
            event::ContractEventDescriptorV1,
            manifest::{ContractErrorTypeDescriptor, ContractErrorVariantDescriptor},
        };
        let artifact = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku Enums { enum Status { Pending = 1, Done = 7 } state Status status; hajimari() { status = Status::Pending; } view fn echo(Status value) authorize(anyone) -> Status { value } }"
        ).expect("compile ordinary enum fixture");
        let mut interface = ProgramMetadata::parse(&artifact)
            .unwrap()
            .contract_interface
            .unwrap();
        validate_enum_types(&interface).expect("compiler binds ordinary enum inventory");
        let descriptor = interface.enum_types[0].clone();
        interface.events.push(ContractEventDescriptorV1 {
            name: "StatusChanged".parse().unwrap(),
            payload_type: EntrypointValueTypeV1 {
                nodes: vec![
                    EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                        name: "Enums::StatusChanged".into(),
                        fields: vec!["status".into()],
                    }),
                    EntrypointValueTypeNodeV1::Enum(descriptor.clone()),
                ],
            },
        });
        assert!(interface.events[0].validate());
        validate_enum_types(&interface).expect("event payload uses authenticated enum identity");
        let original = interface.clone();
        interface.enum_types[0].variants[0].name = "Forged".into();
        assert!(
            validate_enum_types(&interface).is_err(),
            "same code cannot substitute enum schema"
        );
        interface = original.clone();
        interface.enum_types.clear();
        assert!(
            validate_enum_types(&interface).is_err(),
            "referenced enums must be declared"
        );
        interface = original.clone();
        interface.enum_types.push(descriptor.clone());
        assert!(
            validate_enum_types(&interface).is_err(),
            "duplicate declarations reject"
        );
        interface = original.clone();
        interface.error_types.push(ContractErrorTypeDescriptor {
            identity: descriptor.identity.clone(),
            variants: descriptor
                .variants
                .iter()
                .map(|variant| ContractErrorVariantDescriptor {
                    name: variant.name.clone(),
                    code: variant.code,
                })
                .collect(),
        });
        assert!(
            validate_enum_types(&interface).is_err(),
            "error and ordinary enum identities cannot overlap"
        );
        interface = original;
        let EntrypointValueTypeNodeV1::Enum(event_enum) =
            &mut interface.events[0].payload_type.nodes[1]
        else {
            unreachable!()
        };
        event_enum.variants[0].name = "OnlyTheEventIsForged".into();
        assert!(
            validate_enum_types(&interface).is_err(),
            "event payload descriptors require exact table agreement"
        );
    }
    #[test]
    fn callable_table_rejects_missing_roots_schema_substitution_and_invalid_privacy() {
        let bytes = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku Calls { fn echo(bool value) -> bool { value } view fn main(bool value) authorize(anyone) -> bool { echo(value: value) } }"
        ).expect("compile table calls");
        let parsed = ProgramMetadata::parse(&bytes).expect("parse contract");
        let decoded =
            crate::decode_instruction_stream(&bytes[parsed.code_offset..]).expect("decode");
        let mut interface = parsed.contract_interface.expect("CNTR");
        let roots = interface
            .entrypoints
            .iter()
            .map(|entry| entry.entry_pc)
            .collect();
        validate_callable_tables(&interface, &decoded, &roots, false)
            .expect("canonical callable table");
        let original = interface.callables.clone();
        interface.callables.clear();
        assert!(validate_callable_tables(&interface, &decoded, &roots, false).is_err());
        interface.callables = original.clone();
        let public_pc = interface.entrypoints[0].entry_pc;
        interface
            .callables
            .iter_mut()
            .find(|callable| callable.entry_pc == public_pc)
            .unwrap()
            .results
            .nodes[0] = ivm_abi::call::CallTypeNodeV1::Unit;
        assert!(validate_callable_tables(&interface, &decoded, &roots, false).is_err());
        interface.callables = original.clone();
        interface.callables[0].arguments.nodes[0] = ivm_abi::call::CallTypeNodeV1::SecretNumeric(
            ivm_abi::pointer_abi::PointerType::Int as u16,
        );
        assert!(validate_callable_tables(&interface, &decoded, &roots, false).is_err());
        interface.callables = original;
        interface.callables[0].frame_bytes += 1;
        assert!(validate_callable_tables(&interface, &decoded, &roots, false).is_err());
    }
    #[test]
    fn callable_artifacts_reject_the_retired_erased_schema_surface_hash() {
        let mut bytes = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku Cursors { view fn main(StateCursor<int> value) authorize(anyone) -> StateCursor<int> { value } }"
        ).unwrap();
        crate::verify_contract_artifact(&bytes).expect("current cursor artifact");
        // Previous unfinished V1 surface erased every Sum payload and List element type.
        let erased_schema_surface = [
            0x5e, 0x36, 0x46, 0xa0, 0xd2, 0xf4, 0x1, 0xc8, 0x37, 0x24, 0x5, 0x98, 0x55, 0xc9, 0x48,
            0xb4, 0x31, 0x4d, 0xf2, 0x56, 0x43, 0x48, 0xa6, 0xf7, 0xbb, 0x9c, 0xeb, 0x5f, 0xa6,
            0x26, 0xa1, 0x29,
        ];
        let current = ivm_abi::syscalls::compute_abi_hash(ivm_abi::SyscallPolicy::AbiV1);
        assert_ne!(current, erased_schema_surface);
        bytes[17..49].copy_from_slice(&erased_schema_surface);
        assert_eq!(
            crate::verify_contract_artifact(&bytes).expect_err("retired surface must reject"),
            ContractArtifactError::abi_hash_mismatch(current, erased_schema_surface)
        );
    }
    #[test]
    fn callable_tables_bind_cursor_keys_at_public_and_private_boundaries() {
        use ivm_abi::{call::CallTypeNodeV1, entrypoint::EntrypointValueKindV1 as Kind};
        let bytes = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku Cursors { fn echo(StateCursor<int> value) -> StateCursor<int> { value } view fn main(StateCursor<int> value) authorize(anyone) -> StateCursor<int> { echo(value: value) } }"
        ).expect("compile cursor calls");
        let parsed = ProgramMetadata::parse(&bytes).unwrap();
        let decoded = crate::decode_instruction_stream(&bytes[parsed.code_offset..]).unwrap();
        let mut interface = parsed.contract_interface.unwrap();
        let roots = interface
            .entrypoints
            .iter()
            .map(|entry| entry.entry_pc)
            .collect();
        validate_callable_tables(&interface, &decoded, &roots, false).unwrap();
        let public_pc = interface.entrypoints[0].entry_pc;
        let original = interface.callables.clone();
        assert!(
            original.len() >= 2,
            "both public wrapper and private callee must be described"
        );
        for callable in &original {
            assert_eq!(
                callable.arguments.nodes,
                [CallTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(Kind::Int)] })]
            );
            assert_eq!(
                callable.results.nodes,
                [CallTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(Kind::Int)] })]
            );
        }
        for results in [false, true] {
            interface.callables = original.clone();
            let callable = interface
                .callables
                .iter_mut()
                .find(|callable| callable.entry_pc == public_pc)
                .unwrap();
            let words = if results {
                &mut callable.results.nodes
            } else {
                &mut callable.arguments.nodes
            };
            words[0] = CallTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(Kind::Bool)] });
            assert!(
                validate_callable_tables(&interface, &decoded, &roots, false).is_err(),
                "public cursor key substitution (results={results})"
            );
            for index in 0..original.len() {
                interface.callables = original.clone();
                let callable = &mut interface.callables[index];
                let words = if results {
                    &mut callable.results.nodes
                } else {
                    &mut callable.arguments.nodes
                };
                words[0] = CallTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(Kind::Json)] });
                assert!(
                    validate_callable_tables(&interface, &decoded, &roots, false).is_err(),
                    "Json cursor key in callable {index} (results={results})"
                );
            }
        }
    }
    #[test]
    fn callable_schemas_bind_nested_payloads_capacity_and_nominal_identity() {
        use ivm_abi::{call::CallTypeNodeV1 as Node, entrypoint::EntrypointValueKindV1 as Kind};
        let bytes = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku Nested { struct Payload { Option<List<StateCursor<int>, 2>> values; } fn echo(Payload value) -> Payload { value } view fn main(Payload value) authorize(anyone) -> Payload { echo(value: value) } }"
        ).expect("compile complete recursive call schemas");
        let parsed = ProgramMetadata::parse(&bytes).unwrap();
        let decoded = crate::decode_instruction_stream(&bytes[parsed.code_offset..]).unwrap();
        let mut interface = parsed.contract_interface.unwrap();
        let roots = interface
            .entrypoints
            .iter()
            .map(|entry| entry.entry_pc)
            .collect();
        let public_pc = interface.entrypoints[0].entry_pc;
        let original = interface.callables.clone();
        validate_callable_tables(&interface, &decoded, &roots, false).unwrap();
        for result in [false, true] {
            for replacement in [
                Node::Struct {
                    name: "Fixture::OtherPayload".into(),
                    fields: vec!["values".into()],
                },
                Node::Result,
                Node::List { capacity: 3 },
                Node::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(Kind::Bool)] }),
            ] {
                interface.callables = original.clone();
                let callable = interface
                    .callables
                    .iter_mut()
                    .find(|callable| callable.entry_pc == public_pc)
                    .unwrap();
                let schema = if result {
                    &mut callable.results
                } else {
                    &mut callable.arguments
                };
                let index = match replacement {
                    Node::Struct { .. } => 0,
                    Node::Result => 1,
                    Node::List { .. } => 2,
                    _ => 3,
                };
                schema.nodes[index] = replacement;
                assert!(
                    validate_callable_tables(&interface, &decoded, &roots, false).is_err(),
                    "nested substitution (result={result}, node={index})"
                );
            }
            for index in 0..original.len() {
                interface.callables = original.clone();
                let callable = &mut interface.callables[index];
                let schema = if result {
                    &mut callable.results
                } else {
                    &mut callable.arguments
                };
                schema.nodes.pop();
                assert!(
                    validate_callable_tables(&interface, &decoded, &roots, false).is_err(),
                    "missing nested payload (callable={index}, result={result})"
                );
            }
        }
    }
    #[test]
    fn state_cursor_is_an_opaque_value_with_a_supported_scalar_key() {
        use iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1;
        let cursor = EmbeddedStateType::StateCursor(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                        EntrypointValueKindV1::Int,
                    ),
                ],
            },
        );
        assert!(validate_state_type(&cursor, false).is_ok());
        assert_eq!(embedded_state_map_key_type_name(&cursor), None);
        assert!(validate_state_type(&EmbeddedStateType::Option(Box::new(cursor)), false).is_ok());
        assert!(
            validate_state_type(
                &EmbeddedStateType::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Json)] }),
                false
            )
            .is_err()
        );
    }

    use ivm_abi::metadata::EmbeddedStateFieldDescriptor;
    #[test]
    fn nominal_error_catalog_binds_state_schema_without_global_code_collisions() {
        let list = ivm_abi::error_types::list_error_type();
        let numeric = ivm_abi::error_types::numeric_error_type();
        let mut interface = EmbeddedContractInterfaceV1 {
            permissions: Vec::new(),
            events: Vec::new(),
            callables: Vec::new(),
            seiyaku_name: "Errors".into(),
            compiler_fingerprint: "test".into(),
            abi_hash: [0; 32],
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: vec![],
            entrypoints: vec![],
            states: vec![EmbeddedStateDescriptor {
                name: "last_error".into(),
                ty: EmbeddedStateType::Option(Box::new(EmbeddedStateType::Error(list.clone()))),
            }],
            error_messages: Vec::new(),
            enum_types: Vec::new(),
            error_types: vec![list.clone(), numeric],
        };
        validate_error_types(&interface).expect("different types may share enum-local codes");
        interface.error_types[0].variants[0].name = "DifferentMeaning".into();
        assert!(
            validate_error_types(&interface).is_err(),
            "schema substitution must fail"
        );
        interface.error_types[0] = list.clone();
        interface.error_types.push(list);
        assert!(
            validate_error_types(&interface).is_err(),
            "duplicate identity must fail"
        );
        interface.error_types.clear();
        assert!(
            validate_error_types(&interface).is_err(),
            "undeclared state error must fail"
        );
    }
    fn dynamic_hint(
        base_key: &str,
        key_type: &str,
        bound_kind: &str,
        max_keys: u32,
    ) -> DynamicAccessHint {
        DynamicAccessHint {
            base_key: base_key.to_owned(),
            key_type: key_type.to_owned(),
            bound_kind: bound_kind.to_owned(),
            max_keys,
        }
    }
    fn dynamic_read_hints(hints: Vec<DynamicAccessHint>) -> AccessSetHints {
        AccessSetHints {
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            dynamic_reads: hints,
            dynamic_writes: Vec::new(),
        }
    }
    fn state_map(
        name: &str,
        key: EmbeddedStateType,
        value: EmbeddedStateType,
    ) -> EmbeddedStateDescriptor {
        EmbeddedStateDescriptor {
            name: name.to_owned(),
            ty: EmbeddedStateType::StateMap {
                key: Box::new(key),
                value: Box::new(value),
            },
        }
    }
    #[test]
    fn dynamic_hint_key_type_mapping_matches_the_exact_shared_v1_order() {
        let mapped = [
            EmbeddedStateType::Int,
            EmbeddedStateType::Decimal,
            EmbeddedStateType::Quantity,
            EmbeddedStateType::Bool,
            EmbeddedStateType::String,
            EmbeddedStateType::Bytes,
            EmbeddedStateType::DataSpaceId,
            EmbeddedStateType::AccountId,
            EmbeddedStateType::AssetDefinitionId,
            EmbeddedStateType::AssetId,
            EmbeddedStateType::NftId,
            EmbeddedStateType::DomainId,
            EmbeddedStateType::Name,
        ]
        .iter()
        .map(|ty| embedded_state_map_key_type_name(ty).expect("supported key type"))
        .collect::<Vec<_>>();
        assert_eq!(
            mapped,
            ivm_abi::access_hints::DYNAMIC_ACCESS_HINT_KEY_TYPES_V1
        );
    }
    #[test]
    fn source_identifier_policy_rejects_exact_amount_only() {
        assert!(!is_canonical_source_identifier("Amount"));
        assert!(is_canonical_source_identifier("amount"));
        assert!(is_canonical_source_identifier("money"));
    }
    #[test]
    fn dynamic_hints_resolve_exact_declared_state_maps() {
        for (index, (key, key_type)) in [
            (EmbeddedStateType::Int, "int"),
            (EmbeddedStateType::Decimal, "decimal"),
            (EmbeddedStateType::Quantity, "quantity"),
            (EmbeddedStateType::Bool, "bool"),
            (EmbeddedStateType::String, "string"),
            (EmbeddedStateType::Bytes, "bytes"),
            (EmbeddedStateType::DataSpaceId, "DataSpaceId"),
            (EmbeddedStateType::AccountId, "AccountId"),
            (EmbeddedStateType::AssetDefinitionId, "AssetDefinitionId"),
            (EmbeddedStateType::AssetId, "AssetId"),
            (EmbeddedStateType::NftId, "NftId"),
            (EmbeddedStateType::DomainId, "DomainId"),
            (EmbeddedStateType::Name, "Name"),
        ]
        .into_iter()
        .enumerate()
        {
            let state_name = if index == 0 {
                "amount".to_owned()
            } else {
                format!("Map{index}")
            };
            let hints = dynamic_read_hints(vec![dynamic_hint(
                &format!("state:{state_name}"),
                key_type,
                "page",
                64,
            )]);
            let states = [state_map(&state_name, key, EmbeddedStateType::Bool)];
            validate_access_set_hints(Some(&hints)).expect("exact hint must validate");
            validate_dynamic_access_hint_state_maps(Some(&hints), &states)
                .expect("hint must resolve to its exact declared StateMap");
        }
    }
    #[test]
    fn dynamic_hint_shape_aliases_duplicates_and_overflow_reject() {
        let valid = dynamic_hint("state:Orders", "int", "page", 1);
        validate_access_set_hints(Some(&dynamic_read_hints(vec![valid.clone()])))
            .expect("canonical page hint must pass before negative mutations");
        let invalid = [
            dynamic_hint("state:Orders", "int", "range", 1),
            dynamic_hint("state:", "int", "page", 1),
            dynamic_hint("state:Orders/child", "int", "page", 1),
            dynamic_hint("state:Orders", "Numeric", "page", 1),
            dynamic_hint("state:Orders", "int", "bounded", 1),
            dynamic_hint("state:Orders", "int", "page", 0),
            dynamic_hint("state:Orders", "int", "page", 65),
        ];
        for hint in invalid {
            validate_access_set_hints(Some(&dynamic_read_hints(vec![hint])))
                .expect_err("noncanonical dynamic hint must reject");
        }
        validate_access_set_hints(Some(&dynamic_read_hints(vec![valid.clone(), valid])))
            .expect_err("duplicate dynamic hints must reject");
    }
    #[test]
    fn identical_hint_is_allowed_once_in_each_independent_list() {
        let hint = dynamic_hint("state:amount", "quantity", "take", 1);
        let hints = AccessSetHints {
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            dynamic_reads: vec![hint.clone()],
            dynamic_writes: vec![hint],
        };
        let states = [state_map(
            "amount",
            EmbeddedStateType::Quantity,
            EmbeddedStateType::Bool,
        )];
        validate_access_set_hints(Some(&hints))
            .expect("read/write lists have independent duplicate domains");
        validate_dynamic_access_hint_state_maps(Some(&hints), &states)
            .expect("the same exact StateMap hint may appear once in each list");
    }
    #[test]
    fn same_base_with_distinct_bound_fields_is_not_a_duplicate() {
        let hints = dynamic_read_hints(vec![
            dynamic_hint("state:Orders", "int", "page", 1),
            dynamic_hint("state:Orders", "int", "page", 2),
            dynamic_hint("state:Orders", "int", "take", 1),
        ]);
        let states = [state_map(
            "Orders",
            EmbeddedStateType::Int,
            EmbeddedStateType::Bool,
        )];
        validate_access_set_hints(Some(&hints))
            .expect("duplicate identity is the complete four-field record");
        validate_dynamic_access_hint_state_maps(Some(&hints), &states)
            .expect("every distinct record resolves to the same exact StateMap");
    }
    #[test]
    fn dynamic_hints_reject_unknown_scalar_and_mismatched_state_targets() {
        let hints = dynamic_read_hints(vec![dynamic_hint("state:Orders", "int", "take", 1)]);
        for states in [
            Vec::new(),
            vec![EmbeddedStateDescriptor {
                name: "Orders".to_owned(),
                ty: EmbeddedStateType::Int,
            }],
            vec![state_map(
                "Orders",
                EmbeddedStateType::Quantity,
                EmbeddedStateType::Bool,
            )],
        ] {
            validate_dynamic_access_hint_state_maps(Some(&hints), &states)
                .expect_err("hint must resolve to a StateMap with an identical key type");
        }
    }
    fn wide_struct(field_count: usize) -> EmbeddedStateType {
        EmbeddedStateType::Struct {
            name: "Fixture::Wide".to_owned(),
            fields: (0..field_count)
                .map(|index| EmbeddedStateFieldDescriptor {
                    name: format!("field_{index}"),
                    ty: EmbeddedStateType::Bool,
                })
                .collect(),
        }
    }
    fn nested_lists(wrapper_count: usize) -> EmbeddedStateType {
        (0..wrapper_count).fold(EmbeddedStateType::Bool, |element, _| {
            EmbeddedStateType::List {
                element: Box::new(element),
                capacity: 1,
            }
        })
    }
    fn validate_declared_state_type(ty: &EmbeddedStateType) -> Result<(), ContractArtifactError> {
        validate_state_type(ty, true)?;
        validate_runtime_state_schema("value", ty)
    }
    #[test]
    fn durable_reserved_products_require_the_authenticated_builtin_shape() {
        use EmbeddedStateType as T;
        let account = T::Struct {
            name: "kotodama::AccountView".into(),
            fields: vec![
                EmbeddedStateFieldDescriptor {
                    name: "id".into(),
                    ty: T::AccountId,
                },
                EmbeddedStateFieldDescriptor {
                    name: "metadata".into(),
                    ty: T::Json,
                },
            ],
        };
        assert!(validate_declared_state_type(&account).is_ok());
        let page = T::Struct {
            name: "kotodama::QueryPage".into(),
            fields: vec![
                EmbeddedStateFieldDescriptor {
                    name: "items".into(),
                    ty: T::List {
                        element: Box::new(account),
                        capacity: 64,
                    },
                },
                EmbeddedStateFieldDescriptor {
                    name: "next_offset".into(),
                    ty: T::Option(Box::new(T::Int)),
                },
            ],
        };
        assert!(validate_declared_state_type(&page).is_ok());
        for name in [
            "kotodama::AccountView",
            "kotodama::AssetView",
            "kotodama::AssetDefinitionView",
            "kotodama::DomainView",
            "kotodama::NftView",
            "kotodama::QueryPage",
            "kotodama::StatePage",
        ] {
            assert!(
                validate_declared_state_type(&T::Struct {
                    name: name.into(),
                    fields: vec![]
                })
                .is_err(),
                "{name}"
            );
        }
        let mut forged = page;
        if let T::Struct { fields, .. } = &mut forged {
            if let T::List { capacity, .. } = &mut fields[0].ty {
                *capacity = 63;
            }
        }
        assert!(validate_declared_state_type(&forged).is_err());
    }
    #[test]
    fn empty_nominal_state_products_are_admitted_as_unit_slots() {
        let empty = wide_struct(0);
        validate_declared_state_type(&empty).expect("empty nominal state product");
        validate_declared_state_type(&EmbeddedStateType::List {
            element: Box::new(empty),
            capacity: 2,
        })
        .expect("empty nominal state list element");
    }
    #[test]
    fn exact_runtime_state_schema_node_boundary_is_admitted() {
        validate_declared_state_type(&wide_struct(MAX_STATE_VALUE_NODES - 1))
            .expect("one struct plus 255 leaves is exactly 256 runtime schema nodes");
        let error = validate_declared_state_type(&wide_struct(MAX_STATE_VALUE_NODES))
            .expect_err("one struct plus 256 leaves must exceed the runtime schema limit");
        assert!(
            error
                .to_string()
                .contains("256 nodes or levels and 65536 encoded bytes")
        );
    }
    #[test]
    fn state_map_applies_the_exact_runtime_limit_to_its_value_only() {
        let state_map = |value| EmbeddedStateType::StateMap {
            key: Box::new(EmbeddedStateType::AccountId),
            value: Box::new(value),
        };
        validate_declared_state_type(&state_map(wide_struct(MAX_STATE_VALUE_NODES - 1)))
            .expect("the StateMap resource and key are not part of its value schema");
        validate_declared_state_type(&state_map(wide_struct(MAX_STATE_VALUE_NODES)))
            .expect_err("an oversized StateMap value schema must reject at admission");
    }
    #[test]
    fn recursive_list_element_nodes_share_the_outer_schema_budget() {
        let list = |element| EmbeddedStateType::List {
            element: Box::new(element),
            capacity: 64,
        };
        validate_declared_state_type(&list(wide_struct(MAX_STATE_VALUE_NODES - 2)))
            .expect("List + struct + 254 leaves is exactly 256 nodes");
        validate_declared_state_type(&list(wide_struct(MAX_STATE_VALUE_NODES - 1)))
            .expect_err("List element schemas must not receive a fresh 256-node budget");
        validate_declared_state_type(&nested_lists(MAX_STATE_VALUE_NODES - 1))
            .expect("255 nested Lists plus one leaf is the exact depth and node boundary");
        validate_declared_state_type(&nested_lists(MAX_STATE_VALUE_NODES))
            .expect_err("256 nested Lists plus one leaf exceeds both exact runtime limits");
    }
    #[test]
    fn canonical_runtime_schema_byte_limit_is_enforced_at_admission() {
        let ty = EmbeddedStateType::Struct {
            name: format!("Fixture::{}", "S".repeat(MAX_STATE_VALUE_SCHEMA_BYTES)),
            fields: vec![EmbeddedStateFieldDescriptor {
                name: "value".to_owned(),
                ty: EmbeddedStateType::Bool,
            }],
        };
        validate_declared_state_type(&ty)
            .expect_err("a CNTR type whose canonical runtime schema exceeds 64 KiB must reject");
    }
}

#[cfg(test)]
mod nominal_abort_tests;
