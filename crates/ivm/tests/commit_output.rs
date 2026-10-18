//! OUTPUT region and COMMIT_OUTPUT syscall coverage.
use crate::common;
use common::assemble;
use ivm::{IVM, Memory, VMError, encoding, host::IVMHost, instruction, syscalls};
use std::{
    any::Any,
    sync::{Arc, Mutex},
};
const HALT: [u8; 4] = encoding::wide::encode_halt().to_le_bytes();
const SCALL_COMMIT_OUTPUT: [u8; 4] = encoding::wide::encode_sys(
    instruction::wide::system::SCALL,
    syscalls::SYSCALL_COMMIT_OUTPUT as u8,
)
.to_le_bytes();
struct CaptureHost {
    out: Arc<Mutex<Vec<u8>>>,
}
impl IVMHost for CaptureHost {
    fn prepare_syscall(&self, number: u32, _vm: &IVM) -> Result<u64, VMError> {
        match number {
            syscalls::SYSCALL_COMMIT_OUTPUT => Ok(0),
            _ => Err(VMError::UnknownSyscall(number)),
        }
    }
    fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, VMError> {
        match number {
            syscalls::SYSCALL_COMMIT_OUTPUT => {
                *self.out.lock().expect("output mutex poisoned") = vm.read_output().to_vec();
                Ok(0)
            }
            _ => Err(VMError::UnknownSyscall(number)),
        }
    }
    /// Downcast support for hosts with extra methods/state.
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
#[test]
fn test_commit_output_syscall() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut vm = IVM::new(u64::MAX);
    vm.set_host(CaptureHost {
        out: Arc::clone(&captured),
    });
    // program: SCALL COMMIT_OUTPUT; HALT
    let mut code = [0u8; 8];
    code[..4].copy_from_slice(&SCALL_COMMIT_OUTPUT);
    code[4..].copy_from_slice(&HALT);
    let prog = assemble(&code);
    vm.load_program(&prog).unwrap();
    // write some bytes into output region before executing
    vm.store_u32(Memory::OUTPUT_START, 0xdeadbeef).unwrap();
    // run
    vm.run().expect("run failed");
    let out = captured.lock().expect("output mutex poisoned");
    assert_eq!(out.len(), Memory::OUTPUT_SIZE as usize);
    let val = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    assert_eq!(val, 0xdeadbeef);
}
#[test]
fn load_program_clears_output_region() {
    let mut vm = IVM::new(u64::MAX);
    let prog = assemble(&HALT);
    vm.load_program(&prog).expect("load program");
    vm.store_u32(Memory::OUTPUT_START, 0xDEAD_BEEF)
        .expect("write output");
    vm.load_program(&prog).expect("reload program");
    let mut bytes = [0u8; 4];
    vm.memory
        .load_bytes(Memory::OUTPUT_START, &mut bytes)
        .expect("read output");
    assert_eq!(bytes, [0u8; 4]);
    vm.store_u32(Memory::OUTPUT_START, 0x1234_5678)
        .expect("output cursor reset");
}
#[test]
fn load_code_clears_output_region() {
    let mut vm = IVM::new(u64::MAX);
    vm.load_code(&HALT).expect("load code");
    vm.store_u32(Memory::OUTPUT_START, 0xCAFE_BABE)
        .expect("write output");
    vm.load_code(&HALT).expect("reload code");
    let mut bytes = [0u8; 4];
    vm.memory
        .load_bytes(Memory::OUTPUT_START, &mut bytes)
        .expect("read output");
    assert_eq!(bytes, [0u8; 4]);
    vm.store_u32(Memory::OUTPUT_START, 0x0BAD_F00D)
        .expect("output cursor reset");
}
