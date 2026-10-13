//! Instruction decoding for the single-word (32-bit) IVM encoding.
//!
//! Every instruction occupies one 32-bit little-endian word aligned on a
//! 4-byte boundary, so decoding reduces to a bounds check followed by a single
//! load.  Compressed forms predating the wide encoding are no longer supported.
use crate::{
    error::{Perm, VMError},
    memory::Memory,
};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
pub static DECODE_CALLS: AtomicU64 = AtomicU64::new(0);
/// Decode the instruction at `pc` and return its raw word.
pub fn decode(memory: &Memory, pc: u64) -> Result<u32, VMError> {
    #[cfg(test)]
    {
        DECODE_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    if !pc.is_multiple_of(4) {
        return Err(VMError::MemoryAccessViolation {
            addr: pc as u32,
            perm: Perm::EXECUTE,
        });
    }
    let fetch_end = pc.checked_add(4).ok_or(VMError::MemoryAccessViolation {
        addr: pc as u32,
        perm: Perm::EXECUTE,
    })?;
    if fetch_end > memory.code_len() {
        return Err(VMError::MemoryAccessViolation {
            addr: pc as u32,
            perm: Perm::EXECUTE,
        });
    }
    let word = memory.load_instruction_u32(pc)?;
    Ok(word)
}
/// Decode one instruction directly from a code slice.
///
/// This is the allocation-free admission/predecode path. It deliberately has the same alignment,
/// bounds, byte order, errors, and fixed width as [`decode`], without constructing the VM's
/// multi-megabyte memory and Merkle image merely to inspect immutable code.
pub fn decode_slice(code: &[u8], pc: u64) -> Result<u32, VMError> {
    #[cfg(test)]
    {
        DECODE_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    if !pc.is_multiple_of(4) {
        return Err(VMError::MemoryAccessViolation {
            addr: pc as u32,
            perm: Perm::EXECUTE,
        });
    }
    let start = usize::try_from(pc).map_err(|_| VMError::MemoryAccessViolation {
        addr: pc as u32,
        perm: Perm::EXECUTE,
    })?;
    let end = start.checked_add(4).ok_or(VMError::MemoryAccessViolation {
        addr: pc as u32,
        perm: Perm::EXECUTE,
    })?;
    let bytes = code.get(start..end).ok_or(VMError::MemoryAccessViolation {
        addr: pc as u32,
        perm: Perm::EXECUTE,
    })?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("four-byte slice"),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slice_decoder_matches_memory_decoder_without_vm_memory() {
        let words = [0x1122_3344_u32, 0xAABB_CCDD];
        let code = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut memory = Memory::new();
        memory
            .load_code(&code)
            .expect("decoder test program fits code region");
        for pc in [0, 4] {
            assert_eq!(
                decode_slice(&code, pc).unwrap(),
                decode(&memory, pc).unwrap()
            );
        }
        for pc in [1, 8, u64::MAX] {
            for result in [decode_slice(&code, pc), decode(&memory, pc)] {
                assert!(
                    matches!(result, Err(VMError::MemoryAccessViolation { addr, perm }) if addr == pc as u32 && perm == Perm::EXECUTE)
                );
            }
        }
    }
}
