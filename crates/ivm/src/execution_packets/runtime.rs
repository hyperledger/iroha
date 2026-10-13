//! Hooks in the ordinary interpreter; no replay, alternate dispatch or raw input owner.

use super::IVM;
use crate::{
    Memory, PreparedContract, VMError,
    execution_memory::ExecutionMemoryLease,
    execution_packets::{
        self as packets, CaptureError, NativeInvocation, NativePacket, PacketSpace, Storage,
    },
    instruction::wide,
};
use iroha_allocation::AllocationBudget;
use ivm_abi::{call::CallTypeNodeV1, entrypoint::EntrypointValueKindV1};

// Production native capture uses the fresh VM's disabled diagnostic logger.
// This thread-local test observation exercises the same interpreter and packet
// owner with diagnostics enabled, without changing any production mode/API.
#[cfg(test)]
thread_local! {
    static OBSERVE_REGISTER_TRACE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static OBSERVED_REGISTER_EVENTS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

pub(super) struct Recorder {
    output: NativeInvocation,
    pending: Option<Pending>,
    descriptor: [u64; 8],
    root_committed: bool,
    returned: bool,
    gas_stage: usize,
    refusal: Option<CaptureError>,
}
struct Pending {
    instruction: u32,
    first: usize,
    pc: u64,
    cycles: u64,
    protected_depth: u64,
    destination: Option<(usize, u64, bool)>,
    memory: Option<(u64, [u8; 16], u16)>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some((address, bytes, mask)) = &mut self.memory {
            iroha_crypto::zeroize_value_for_confidential_discard(address);
            iroha_crypto::zeroize_value_for_confidential_discard(bytes);
            iroha_crypto::zeroize_value_for_confidential_discard(mask);
        }
        if let Some((register, value, tag)) = &mut self.destination {
            iroha_crypto::zeroize_value_for_confidential_discard(register);
            iroha_crypto::zeroize_value_for_confidential_discard(value);
            iroha_crypto::zeroize_value_for_confidential_discard(tag);
        }
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.instruction);
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.first);
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.pc);
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.cycles);
        iroha_crypto::zeroize_value_for_confidential_discard(&mut self.protected_depth);
    }
}
impl Recorder {
    fn word(
        &mut self,
        clock: usize,
        space: PacketSpace,
        generation: u16,
        index: u32,
        write: bool,
        [before, after]: [u64; 2],
    ) {
        let mut packet = NativePacket::zero();
        packet.space = space as u8;
        packet.generation = generation;
        packet.index = index;
        packet.clock = clock as u32;
        packet.write = write;
        packet.before[..8].copy_from_slice(&before.to_le_bytes());
        packet.after[..8].copy_from_slice(&after.to_le_bytes());
        self.output.packets.put(clock, packet);
    }
    fn register(
        &mut self,
        clock: usize,
        index: usize,
        write: bool,
        (before, before_tag): (u64, bool),
        (after, after_tag): (u64, bool),
    ) {
        if write && index == 0 {
            return;
        }
        let mut packet = NativePacket::zero();
        packet.space = PacketSpace::Register as u8;
        packet.index = index as u32;
        packet.clock = clock as u32;
        packet.write = write;
        packet.before[..8].copy_from_slice(&before.to_le_bytes());
        packet.after[..8].copy_from_slice(&after.to_le_bytes());
        packet.before_private = u16::from(before_tag);
        packet.after_private = u16::from(after_tag);
        self.output.packets.put(clock, packet);
    }
    fn memory(
        &mut self,
        clock: usize,
        address: u64,
        write: bool,
        before: [u8; 16],
        after: [u8; 16],
    ) {
        let mut packet = NativePacket::zero();
        packet.space = PacketSpace::Memory as u8;
        packet.index = (address / 16) as u32;
        packet.clock = clock as u32;
        packet.write = write;
        packet.before = before;
        packet.after = after;
        self.output.packets.put(clock, packet);
    }
    fn refusal(&mut self, reason: CaptureError) -> VMError {
        self.refusal = Some(reason);
        // Private control signal. Only capture_public_leaf_root installs this owner and
        // translates it back; this is never returned as a transaction verdict.
        VMError::ExecutionDeferred(crate::error::ExecutionDeferral::VerifierArtifactsUnavailable)
    }
    pub(super) fn gas_debit(&mut self, before: u64, cost: u64) -> Result<(), VMError> {
        let first = if !self.root_committed {
            8
        } else if self
            .pending
            .as_ref()
            .is_some_and(|p| wide::opcode(p.instruction) == wide::control::JALR)
        {
            packets::RETURN_FIRST + 22
        } else {
            return Err(self.refusal(CaptureError::Unsupported));
        };
        if self.gas_stage >= 2 {
            return Err(self.refusal(CaptureError::Unsupported));
        }
        self.word(
            first + self.gas_stage,
            PacketSpace::Owner,
            0,
            33,
            true,
            [before, before - cost],
        );
        self.gas_stage += 1;
        Ok(())
    }
}

impl IVM {
    #[cfg(test)]
    pub(crate) fn native_register_trace_enabled_for_test() -> bool {
        OBSERVE_REGISTER_TRACE.get()
    }

    #[cfg(test)]
    pub(crate) fn with_native_register_trace_for_test<T>(
        run: impl FnOnce() -> T,
    ) -> (T, Option<usize>) {
        struct Restore(bool, Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                OBSERVE_REGISTER_TRACE.set(self.0);
                OBSERVED_REGISTER_EVENTS.set(self.1);
            }
        }
        let _restore = Restore(
            OBSERVE_REGISTER_TRACE.replace(true),
            OBSERVED_REGISTER_EVENTS.replace(None),
        );
        let result = run();
        (result, OBSERVED_REGISTER_EVENTS.get())
    }

    pub(crate) fn capture_public_leaf_root(
        contract: PreparedContract,
        selector: &str,
        initial_gas: u64,
        parent: &mut ExecutionMemoryLease,
        budget: &AllocationBudget,
    ) -> Result<NativeInvocation, CaptureError> {
        let metadata = contract.metadata();
        if metadata.abi_version != 1
            || metadata.mode != crate::ivm_mode::ZK
            || !(1..=packets::MAX_STEPS as u64).contains(&metadata.max_cycles)
            || contract.artifact().len() - contract.code_offset() > packets::MAX_STEPS * 4
        {
            return Err(CaptureError::Unsupported);
        }
        let interface = contract.contract_interface();
        let entrypoint = interface
            .entrypoints
            .iter()
            .position(|entry| entry.name == selector)
            .ok_or(CaptureError::Unsupported)?;
        let public = &interface.entrypoints[entrypoint];
        let callable = interface
            .callables
            .iter()
            .find(|call| call.entry_pc == public.entry_pc)
            .ok_or(CaptureError::Unsupported)?;
        if public.argument_schema.is_some()
            || !callable.arguments.nodes.is_empty()
            || !matches!(
                callable.results.nodes.as_slice(),
                [CallTypeNodeV1::Unit] | [CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)]
            )
        {
            return Err(CaptureError::Unsupported);
        }
        let packets = Storage::new(parent)?;
        let mut vm = Self::try_new_with_memory_budget(initial_gas, budget)
            .map_err(CaptureError::Execution)?;
        vm.load_prepared(&contract)
            .map_err(CaptureError::Execution)?;
        vm.select_entrypoint(selector)
            .map_err(CaptureError::Execution)?;
        #[cfg(test)]
        vm.set_zk_trace_enabled(OBSERVE_REGISTER_TRACE.get());
        let mut recorder = Recorder {
            output: NativeInvocation {
                contract,
                entrypoint,
                initial_gas,
                final_gas: 0,
                cycles: 0,
                instructions: 0,
                packets,
            },
            pending: None,
            descriptor: [0; 8],
            root_committed: false,
            returned: false,
            gas_stage: 0,
            refusal: None,
        };
        // The VM was constructed here and has never been exposed to a caller.
        // Only these nonzero initial cells exist before native root installation.
        recorder.word(0, PacketSpace::Owner, 0, 33, true, [0, initial_gas]);
        recorder.word(1, PacketSpace::Owner, 0, 32, true, [0, vm.pc]);
        recorder.word(2, PacketSpace::Owner, 0, 35, true, [0, 1]);
        recorder.word(
            3,
            PacketSpace::Owner,
            0,
            20,
            true,
            [0, vm.memory.stack_top()],
        );
        recorder.word(4, PacketSpace::Owner, 0, 21, true, [0, Memory::HEAP_START]);
        vm.native_packets = Some(recorder);
        // Syscalls are refused at fetch before base gas or a host callback.
        // The ordinary no-argument root needs no host-provided input.
        let result = vm.run_with_host(&mut crate::host::DefaultHost::new());
        #[cfg(test)]
        if OBSERVE_REGISTER_TRACE.get() {
            OBSERVED_REGISTER_EVENTS.set(Some(
                vm.proof_register_log_handle()
                    .unwrap()
                    .lock()
                    .as_slice()
                    .len(),
            ));
        }
        let mut recorder = vm
            .native_packets
            .take()
            .expect("native owner retained throughout run");
        if let Some(refusal) = recorder.refusal.take() {
            return Err(refusal);
        }
        result.map_err(CaptureError::Execution)?;
        if !recorder.root_committed
            || !recorder.returned
            || recorder.pending.is_some()
            || recorder.gas_stage != 2
        {
            return Err(CaptureError::Unsupported);
        }
        recorder.output.final_gas = vm.gas_remaining;
        recorder.output.cycles = vm.cycles;
        Ok(recorder.output)
    }

    pub(super) fn native_root_committed(&mut self) {
        let Some(recorder) = self.native_packets.as_mut() else {
            return;
        };
        assert!(!recorder.root_committed);
        recorder.descriptor = self
            .memory
            .call_frames
            .native_packet_descriptor()
            .expect("successful root owns one frame");
        for (offset, register) in [10, 11, 12, 13, 31, 1].into_iter().enumerate() {
            recorder.register(
                16 + offset,
                register,
                true,
                (0, false),
                (self.registers.get(register), self.registers.tag(register)),
            );
        }
        recorder.word(
            22,
            PacketSpace::Owner,
            0,
            21,
            true,
            [
                Memory::HEAP_START,
                Memory::HEAP_START + self.memory.heap_allocated_len(),
            ],
        );
        // The bounded profile has exactly one successful frame generation. It
        // belongs to this run's optional owner, never to caller input or depth.
        recorder.word(24, PacketSpace::Owner, 0, 1, true, [0, 1]);
        recorder.word(25, PacketSpace::Owner, 0, 0, true, [0, 1]);
        recorder.word(26, PacketSpace::Owner, 1, 2, true, [0, 0]);
        for (index, value) in recorder.descriptor.into_iter().enumerate() {
            recorder.word(
                32 + index,
                PacketSpace::Owner,
                1,
                4 + index as u32,
                true,
                [0, value],
            );
        }
        recorder.word(
            40,
            PacketSpace::Owner,
            1,
            12,
            true,
            [
                0,
                self.contract_outer_return_pc
                    .expect("root sentinel installed"),
            ],
        );
        recorder.root_committed = true;
        recorder.gas_stage = 0;
    }

    pub(super) fn native_preflight_step(
        &mut self,
        instruction: u32,
        cost: u64,
    ) -> Result<(), VMError> {
        let Some(recorder) = self.native_packets.as_mut() else {
            return Ok(());
        };
        let opcode = wide::opcode(instruction);
        let scalar = packets::public_scalar_operands(instruction);
        if (scalar.is_none()
            && !matches!(
                opcode,
                wide::memory::LDI64
                    | wide::memory::LOAD64
                    | wide::memory::STORE64
                    | wide::control::JALR
            ))
            || (opcode == wide::control::JALR
                && (wide::rd(instruction) != 0
                    || wide::rs1(instruction) != 1
                    || wide::imm8(instruction) != 0))
        {
            return Err(recorder.refusal(CaptureError::Unsupported));
        }
        if recorder.pending.is_some()
            || recorder.returned
            || recorder.output.instructions >= packets::MAX_STEPS
        {
            return Err(recorder.refusal(CaptureError::Capacity));
        }
        if scalar.is_some_and(|(left, right)| {
            self.registers.tag(left) || right.is_some_and(|right| self.registers.tag(right))
        }) {
            // This optional producer covers public operands only. Ordinary
            // interpreter tag semantics are unchanged when no owner is present.
            return Err(recorder.refusal(CaptureError::Unsupported));
        }
        if matches!(opcode, wide::memory::LOAD64 | wide::memory::STORE64) {
            let register = if opcode == wide::memory::STORE64 {
                wide::rd(instruction)
            } else {
                wide::rs1(instruction)
            };
            let address = self
                .registers
                .get(register)
                .wrapping_add_signed(i64::from(wide::imm8(instruction)));
            let end = address.checked_add(8);
            let stack = address >= recorder.descriptor[0]
                && end.is_some_and(|end| end <= recorder.descriptor[1]);
            let result = opcode == wide::memory::STORE64
                && address >= recorder.descriptor[4]
                && end.is_some_and(|end| end <= recorder.descriptor[5]);
            if !address.is_multiple_of(8) || !(stack || result) {
                return Err(recorder.refusal(CaptureError::Unsupported));
            }
        }
        let returning = opcode == wide::control::JALR;
        let first = if returning {
            packets::RETURN_FIRST
        } else {
            packets::ROOT_SLOTS + recorder.output.instructions * packets::STEP_SLOTS
        };
        let clocks = if returning {
            packets::RETURN_DISPATCH
        } else {
            packets::COMPACT_DISPATCH
        };
        let protected_depth = self.contract_return_stack.len() as u64;
        if !returning {
            recorder.word(
                first + clocks[14],
                PacketSpace::Owner,
                0,
                36,
                false,
                [protected_depth, protected_depth],
            );
        }
        recorder.word(
            first + clocks[0],
            PacketSpace::Owner,
            0,
            32,
            false,
            [self.pc, self.pc],
        );
        recorder.word(
            first + clocks[1],
            PacketSpace::Owner,
            0,
            33,
            true,
            [self.gas_remaining, self.gas_remaining - cost],
        );
        let destination =
            if scalar.is_some() || matches!(opcode, wide::memory::LDI64 | wide::memory::LOAD64) {
                let index = wide::rd(instruction);
                Some((index, self.registers.get(index), self.registers.tag(index)))
            } else {
                None
            };
        let read = |recorder: &mut Recorder, offset, index| {
            let value = self.registers.get(index);
            let tag = self.registers.tag(index);
            recorder.register(first + offset, index, false, (value, tag), (value, tag));
        };
        if let Some((left, right)) = scalar {
            read(recorder, clocks[15], left);
            if let Some(right) = right {
                read(recorder, clocks[16], right);
            }
        }
        match opcode {
            wide::memory::LOAD64 => read(recorder, clocks[4], wide::rs1(instruction)),
            wide::memory::STORE64 => {
                read(recorder, clocks[4], wide::rd(instruction));
                read(recorder, clocks[5], wide::rs1(instruction));
            }
            wide::control::JALR => {
                read(recorder, clocks[2], 1);
                let protected = self.contract_outer_return_pc.expect("native root sentinel");
                recorder.word(
                    first + clocks[3],
                    PacketSpace::Owner,
                    1,
                    12,
                    false,
                    [protected, protected],
                );
            }
            _ => {}
        }
        let memory = if matches!(opcode, wide::memory::LOAD64 | wide::memory::STORE64) {
            let register = if opcode == wide::memory::STORE64 {
                wide::rd(instruction)
            } else {
                wide::rs1(instruction)
            };
            let address = self
                .registers
                .get(register)
                .wrapping_add_signed(i64::from(wide::imm8(instruction)));
            // Only successful aligned memory instructions are publishable. A
            // malformed address remains the ordinary interpreter's own fault.
            self.memory.native_packet_cell(address & !15).map(|bytes| {
                (
                    address & !15,
                    bytes,
                    self.memory
                        .call_frames
                        .native_packet_initialized(address & !15),
                )
            })
        } else {
            None
        };
        recorder.pending = Some(Pending {
            instruction,
            first,
            pc: self.pc,
            cycles: self.cycles,
            protected_depth,
            destination,
            memory,
        });
        recorder.output.instructions += 1;
        Ok(())
    }

    pub(super) fn native_finish_step(&mut self) {
        let Some(recorder) = self.native_packets.as_mut() else {
            return;
        };
        let Some(pending) = recorder.pending.take() else {
            return;
        };
        let opcode = wide::opcode(pending.instruction);
        let returning = opcode == wide::control::JALR;
        let clocks = if returning {
            packets::RETURN_DISPATCH
        } else {
            packets::COMPACT_DISPATCH
        };
        if returning {
            recorder.word(
                pending.first + clocks[14],
                PacketSpace::Owner,
                0,
                36,
                true,
                [
                    pending.protected_depth,
                    self.contract_return_stack.len() as u64,
                ],
            );
        }
        if let Some((index, before, tag)) = pending.destination {
            let offset = clocks[17];
            recorder.register(
                pending.first + offset,
                index,
                true,
                (before, tag),
                (self.registers.get(index), self.registers.tag(index)),
            );
        }
        if let Some((address, before, initialized)) = pending.memory {
            let after = self
                .memory
                .native_packet_cell(address)
                .expect("successful memory access has physical backing");
            let write = opcode == wide::memory::STORE64;
            recorder.memory(pending.first + 6, address, write, before, after);
            let after_initialized = self.memory.call_frames.native_packet_initialized(address);
            recorder.word(
                pending.first + 7,
                PacketSpace::Initialization,
                1,
                (address / 16) as u32,
                write,
                [u64::from(initialized), u64::from(after_initialized)],
            );
        }
        recorder.word(
            pending.first + clocks[18],
            PacketSpace::Owner,
            0,
            32,
            true,
            [pending.pc, self.pc],
        );
        recorder.word(
            pending.first + clocks[19],
            PacketSpace::Owner,
            0,
            34,
            true,
            [pending.cycles, self.cycles],
        );
        recorder.word(
            pending.first + clocks[20],
            PacketSpace::Owner,
            0,
            35,
            true,
            [1, u64::from(!self.halted)],
        );
        #[cfg(test)]
        packets::tests::panic_if_requested();
    }

    pub(super) fn native_before_return(&mut self) {
        let Some(recorder) = self.native_packets.as_mut() else {
            return;
        };
        let first = packets::RETURN_FIRST;
        for (offset, index) in [10, 11, 31].into_iter().enumerate() {
            let value = self.registers.get(index);
            recorder.register(
                first + 15 + offset,
                index,
                false,
                (value, self.registers.tag(index)),
                (value, self.registers.tag(index)),
            );
        }
        for (offset, index) in [10, 11, 8, 9].into_iter().enumerate() {
            let value = recorder.descriptor[index - 4];
            recorder.word(
                first + 18 + offset,
                PacketSpace::Owner,
                1,
                index as u32,
                false,
                [value, value],
            );
        }
        let start = recorder.descriptor[4];
        let end = recorder.descriptor[5];
        // Every mandatory slot is already allocated. Read the actual bitmap
        // before the native owner pops it; inactive cells remain canonical zero.
        for offset in 0..packets::RETURN_CELLS {
            let address = (start & !15) + offset as u64 * 16;
            if address < end {
                let mask = self.memory.call_frames.native_packet_initialized(address);
                recorder.word(
                    first + packets::SCAN_OFFSET + 2 * offset,
                    PacketSpace::Initialization,
                    1,
                    (address / 16) as u32,
                    false,
                    [u64::from(mask), u64::from(mask)],
                );
            }
        }
        // Actual public-leaf validation reads this memory after its NODE and WORD gas.
        let bytes = self
            .memory
            .native_packet_cell(start & !15)
            .expect("validated public leaf has physical memory");
        recorder.memory(first + 24, start & !15, false, bytes, bytes);
    }

    pub(super) fn native_root_returned(&mut self) {
        let Some(recorder) = self.native_packets.as_mut() else {
            return;
        };
        let first = packets::RETURN_FIRST;
        recorder.word(first + 45, PacketSpace::Owner, 0, 1, false, [1, 1]);
        recorder.word(first + 46, PacketSpace::Owner, 0, 0, true, [1, 0]);
        recorder.word(first + 47, PacketSpace::Owner, 1, 2, false, [0, 0]);
        recorder.returned = true;
    }

    pub(super) fn native_padding_completed(&mut self, before_gas: u64, before_cycles: u64) {
        let Some(recorder) = self.native_packets.as_mut() else {
            return;
        };
        recorder.word(
            packets::PADDING_FIRST,
            PacketSpace::Owner,
            0,
            33,
            true,
            [before_gas, self.gas_remaining],
        );
        recorder.word(
            packets::PADDING_FIRST + 1,
            PacketSpace::Owner,
            0,
            34,
            true,
            [before_cycles, self.cycles],
        );
    }
}
