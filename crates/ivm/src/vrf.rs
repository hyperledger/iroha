//! Canonical VRF syscall payloads.
pub use ivm_abi::host_payload::{
    MAX_VRF_VERIFY_BATCH_ITEMS_V1, MAX_VRF_VERIFY_PAYLOAD_BYTES_V1, VRF_VERIFY_DECODE_LIMITS_V1,
    VrfVerifyBatchRequest, VrfVerifyRequest,
};

/// Exact epoch-seed lookup and output cost, independent of cache warmth.
#[must_use]
pub const fn epoch_seed_gas(found: bool) -> u64 {
    crate::gas::STATE_QUERY_GAS_BASE + 8 + if found { 32 } else { 0 }
}

/// Publish an exact committed epoch seed as a nullable public Blob pointer.
///
/// The epoch is a checked `u64` in r10. Only r10 changes on success; a missing
/// epoch returns zero. Output construction uses fixed stack storage, and guest
/// memory admission retains the original VM allocation owner.
///
/// # Errors
/// Returns deterministic gas, taint or guest-memory faults, preserving local
/// allocation deferrals. Failure leaves the caller's result registers untouched.
pub fn publish_epoch_seed(
    vm: &mut crate::IVM,
    seed: Option<&[u8; 32]>,
) -> Result<u64, crate::VMError> {
    vm.ensure_public_register(10)?;
    let gas = epoch_seed_gas(seed.is_some());
    crate::host::preflight_reserved_syscall_gas(vm, gas)?;
    if vm.remaining_gas() < gas {
        return Err(crate::VMError::OutOfGas);
    }
    let pointer = if let Some(seed) = seed {
        let mut envelope = [0_u8; 7 + 32 + 32];
        envelope[..2].copy_from_slice(&(crate::PointerType::Blob as u16).to_be_bytes());
        envelope[2] = 1;
        envelope[3..7].copy_from_slice(&32_u32.to_be_bytes());
        envelope[7..39].copy_from_slice(seed);
        envelope[39..].copy_from_slice(iroha_crypto::Hash::new(seed).as_ref());
        vm.alloc_host_tlv(&envelope)?
    } else {
        0
    };
    vm.set_register(10, pointer);
    Ok(gas)
}

#[cfg(test)]
mod epoch_seed_tests {
    use super::*;

    #[test]
    fn epoch_seed_publication_is_fixed_deterministic_and_preserves_other_registers() {
        let mut vm = crate::IVM::new(10_000);
        vm.set_register(10, u64::MAX);
        vm.set_register(11, 71);
        assert_eq!(
            publish_epoch_seed(&mut vm, None).unwrap(),
            epoch_seed_gas(false)
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 71);
        vm.set_register(10, 7);
        assert_eq!(
            publish_epoch_seed(&mut vm, Some(&[0x42; 32])).unwrap(),
            epoch_seed_gas(true)
        );
        let pointer = vm.register(10);
        let tlv = vm.validate_tlv(pointer).unwrap();
        assert_eq!(tlv.type_id, crate::PointerType::Blob);
        assert_eq!(tlv.payload, &[0x42; 32]);
        assert_eq!(vm.register(11), 71);
        vm.set_register(10, 7);
        vm.set_gas_limit(epoch_seed_gas(true) - 1);
        let heap = vm.alloc_heap(0).unwrap();
        assert!(matches!(
            publish_epoch_seed(&mut vm, Some(&[0x42; 32])),
            Err(crate::VMError::OutOfGas)
        ));
        assert_eq!(vm.register(10), 7);
        assert_eq!(vm.register(11), 71);
        assert_eq!(vm.alloc_heap(0).unwrap(), heap);
    }
    #[test]
    fn epoch_seed_publication_rejects_private_epoch_without_revealing_presence() {
        let mut vm = crate::IVM::new(10_000);
        vm.set_zk_mode(true).unwrap();
        vm.set_register(10, 7);
        vm.set_register(11, 71);
        vm.registers.set_tag(10, true);
        for seed in [None, Some(&[0x42; 32])] {
            assert_eq!(
                publish_epoch_seed(&mut vm, seed),
                Err(crate::VMError::PrivacyViolation)
            );
            assert_eq!(vm.register(10), 7);
            assert_eq!(vm.register(11), 71);
        }
    }

    #[test]
    fn default_host_rejects_seed_lookup_without_a_world_snapshot() {
        use crate::IVMHost;
        let mut host = crate::host::DefaultHost::new();
        let mut vm = crate::IVM::new(10_000);
        vm.set_register(10, 7);
        vm.set_register(11, 71);
        let number = crate::syscalls::SYSCALL_VRF_EPOCH_SEED;
        assert_eq!(
            host.prepare_syscall(number, &vm).unwrap(),
            epoch_seed_gas(false)
        );
        assert_eq!(
            host.syscall(number, &mut vm),
            Err(crate::VMError::metered_not_implemented(
                epoch_seed_gas(false),
                number
            ))
        );
        assert_eq!(vm.register(10), 7);
        assert_eq!(vm.register(11), 71);
    }
}
