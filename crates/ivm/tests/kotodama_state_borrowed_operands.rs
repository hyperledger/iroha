//! Borrowed state/path operands retain real schema, lifetime, metering and quantity checks.

use iroha_crypto::Hash;
use iroha_model_base::{name::Name, state_path::StatePath};
use iroha_primitives::numeric_abi::QuantityValueV1;
use ivm::{
    CoreHost, IVM, Memory, PointerType, ProgramMetadata, VMError, encoding,
    host::{DefaultHost, IVMHost},
    instruction,
    numeric::NumericFaultV1,
    syscalls,
};
use ivm_abi::state_value::StateValueKindV1;
use kotodama_lang::compiler::Compiler;
mod common;

fn compile(source: &str) -> Vec<u8> {
    Compiler::new()
        .compile_source(source)
        .expect("compile canonical typed state contract")
}
fn envelope(kind: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(kind as u16).to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(Hash::new(payload).as_ref());
    bytes
}
fn name_path(base: &str, key: &str) -> String {
    let name: Name = key.parse().unwrap();
    format!(
        "{base}/{}",
        hex::encode(envelope(
            PointerType::Name,
            &norito::to_bytes(&name).unwrap()
        ))
    )
}
fn quantity(record: &[u8]) -> String {
    let bytes = common::decode_pointer_state_value(record, StateValueKindV1::Quantity);
    let tlv = ivm::pointer_abi::validate_tlv_bytes(&bytes).unwrap();
    assert_eq!(tlv.type_id, PointerType::Quantity);
    QuantityValueV1::decode_frame(tlv.payload)
        .unwrap()
        .into_quantity()
        .to_string()
}
fn source(amount: u64) -> String {
    format!(
        r#"seiyaku BorrowedState {{ permission WriteState;
        state StateMap<Name, quantity> Balances;
        state quantity Total;
        fn move_amount(Name source, Name destination, quantity amount) {{
            let quantity zero = 0;
            let available = Balances.get(source).unwrap_or(zero);
            let received = Balances.get(destination).unwrap_or(zero);
            let remainder = available - amount;
            Balances[source] = remainder;
            Balances[destination] = received + amount;
        }}
        kotoage fn main() authorize(WriteState) -> bool {{
            let left = Name::parse("left");
            let right = Name::parse("right");
            let quantity zero = 0;
            let quantity supply = 100;
            let quantity amount = {amount};
            Balances[left] = supply;
            Balances[right] = zero;
            Total = supply;
            move_amount(source: left, destination: right, amount: amount);
            return Balances.get(left).unwrap_or(zero) + Balances.get(right).unwrap_or(zero) == Total;
        }}
    }}"#
    )
}
fn run(program: &[u8], host: &mut dyn IVMHost) -> (IVM, Result<(), VMError>) {
    let mut vm = IVM::new(1_000_000);
    vm.load_program(program).unwrap();
    common::select_kotodama_entrypoint(&mut vm, program, "main");
    let result = vm.run_with_host(host);
    (vm, result)
}
fn fault(error: &VMError) -> Option<NumericFaultV1> {
    match error {
        VMError::NumericFault(fault) => Some(*fault),
        VMError::Metered { source, .. } => fault(source),
        _ => None,
    }
}

#[test]
fn borrowed_state_operands_keep_quantity_conservation_and_owned_results_on_both_hosts() {
    for amount in [0, 27, 100] {
        let program = compile(&source(amount));
        let parsed = ProgramMetadata::parse(&program).unwrap();
        assert_eq!(
            parsed.contract_interface.as_ref().unwrap().callables.len(),
            2
        );
        let publish = encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
        );
        assert!(
            !program[parsed.code_offset..]
                .chunks_exact(4)
                .any(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) == publish)
        );
        let mut default = DefaultHost::new();
        let (vm, outcome) = run(&program, &mut default);
        outcome.unwrap();
        assert_eq!(vm.public_call_result_word(0), Ok(1));
        assert!(vm.remaining_gas() < 1_000_000);
        let mut host = CoreHost::new();
        let mut vm = IVM::new(1_000_000);
        vm.load_program(&program).unwrap();
        common::select_kotodama_entrypoint(&mut vm, &program, "main");
        let budget = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
        let mut steps =
            ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(8192, &budget).unwrap();
        vm.run_with_host_diagnostic_steps(&mut host, &mut steps)
            .unwrap();
        assert_eq!(vm.public_call_result_word(0), Ok(1));
        for number in [
            syscalls::SYSCALL_STATE_GET,
            syscalls::SYSCALL_STATE_SET,
            syscalls::SYSCALL_POINTER_TO_NORITO,
            syscalls::SYSCALL_BUILD_PATH_KEY_NORITO,
        ] {
            let word = encoding::wide::encode_sys(instruction::wide::system::SCALL, number as u8);
            let calls = steps
                .records()
                .iter()
                .filter(|step| step.instruction == Some(word))
                .collect::<Vec<_>>();
            assert!(!calls.is_empty(), "real typed consumer {number} executed");
            assert!(
                calls
                    .iter()
                    .all(|step| step.before.gas_remaining > step.after.gas_remaining)
            );
        }
        assert!(
            steps
                .records()
                .iter()
                .all(|step| step.instruction != Some(publish))
        );
        drop(vm);
        // The retaining STATE_SET boundary still copies/owns canonical bytes. It
        // must not retain pointers into the now-destroyed VM literal/INPUT/HEAP.
        assert_eq!(
            quantity(&host.state_bytes(&name_path("Balances", "left")).unwrap()),
            (100 - amount).to_string()
        );
        assert_eq!(
            quantity(&host.state_bytes(&name_path("Balances", "right")).unwrap()),
            amount.to_string()
        );
        assert_eq!(quantity(&host.state_bytes("Total").unwrap()), "100");
    }
}

#[test]
fn borrowed_state_operands_keep_underflow_before_any_transfer_write() {
    let program = compile(&source(101));
    let mut default = DefaultHost::new();
    let (_, result) = run(&program, &mut default);
    assert_eq!(
        fault(&result.unwrap_err()),
        Some(NumericFaultV1::QuantityUnderflow)
    );
    let mut host = CoreHost::new();
    let (vm, result) = run(&program, &mut host);
    assert_eq!(
        fault(&result.unwrap_err()),
        Some(NumericFaultV1::QuantityUnderflow)
    );
    drop(vm);
    assert_eq!(
        quantity(&host.state_bytes(&name_path("Balances", "left")).unwrap()),
        "100"
    );
    assert_eq!(
        quantity(&host.state_bytes(&name_path("Balances", "right")).unwrap()),
        "0"
    );
    assert_eq!(quantity(&host.state_bytes("Total").unwrap()), "100");
}

#[test]
fn borrowed_heap_state_payload_is_copied_and_invalid_envelopes_cannot_mutate_it() {
    let program = compile(
        r#"seiyaku OwnedState { permission WriteState;
        state int Counter;
        kotoage fn main() authorize(WriteState) { Counter = 1; }
    }"#,
    );
    let mut vm = IVM::new(1_000_000);
    vm.load_program(&program).unwrap();
    let path: StatePath = "Counter".parse().unwrap();
    let path = envelope(PointerType::NoritoBytes, &norito::to_bytes(&path).unwrap());
    let value = common::encode_int_state_value(42);
    let value_tlv = envelope(PointerType::NoritoBytes, &value);
    let path_ptr = vm.alloc_heap(path.len() as u64).unwrap();
    let value_ptr = vm.alloc_heap(value_tlv.len() as u64).unwrap();
    vm.memory.store_bytes(path_ptr, &path).unwrap();
    vm.memory.store_bytes(value_ptr, &value_tlv).unwrap();
    vm.set_register(10, path_ptr);
    vm.set_register(11, value_ptr);
    let mut host = CoreHost::new();
    assert!(
        host.prepare_syscall(syscalls::SYSCALL_STATE_SET, &vm)
            .unwrap()
            > 0
    );
    host.syscall(syscalls::SYSCALL_STATE_SET, &mut vm).unwrap();
    assert_eq!(host.state_bytes("Counter"), Some(value.clone()));
    let mut damaged = value_tlv.clone();
    *damaged.last_mut().unwrap() ^= 1;
    vm.memory.store_bytes(value_ptr, &damaged).unwrap();
    assert_eq!(
        host.syscall(syscalls::SYSCALL_STATE_SET, &mut vm),
        Err(VMError::NoritoInvalid)
    );
    assert_eq!(host.state_bytes("Counter"), Some(value.clone()));
    // A well-formed envelope for a different declared state schema is also invalid.
    let name: Name = "wrong_schema".parse().unwrap();
    let wrong = common::encode_pointer_state_value(
        StateValueKindV1::Name,
        PointerType::Name,
        &norito::to_bytes(&name).unwrap(),
    );
    let wrong = envelope(PointerType::NoritoBytes, &wrong);
    let wrong_ptr = vm.alloc_heap(wrong.len() as u64).unwrap();
    vm.memory.store_bytes(wrong_ptr, &wrong).unwrap();
    vm.set_register(11, wrong_ptr);
    assert_eq!(
        host.syscall(syscalls::SYSCALL_STATE_SET, &mut vm),
        Err(VMError::NoritoInvalid)
    );
    assert_eq!(host.state_bytes("Counter"), Some(value.clone()));
    vm.set_register(10, Memory::STACK_START);
    assert_eq!(
        host.prepare_syscall(syscalls::SYSCALL_STATE_SET, &vm),
        Err(VMError::NoritoInvalid)
    );
    assert_eq!(host.state_bytes("Counter"), Some(value.clone()));
    drop(vm);
    assert_eq!(host.state_bytes("Counter"), Some(value));
}
