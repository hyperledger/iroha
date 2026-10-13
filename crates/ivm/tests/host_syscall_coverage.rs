//! ABI v1 host syscall coverage checks.
use iroha_crypto::{Hash, PublicKey};
use ivm::{
    CoreHost, IVM, IVMHost, VMError, gas,
    host::{
        DefaultHost, HostSyscallGasClass, HostSyscallGasFormula, HostSyscallGasParameters,
        HostSyscallQuoteStrategy, abi_v1_host_syscall_metering_registry,
        host_syscall_metering_spec, registered_host_syscall_gas_formula,
    },
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    pointer_abi::PointerType,
    syscall_metering::SyscallMetering,
    syscalls,
};
use std::str::FromStr;
fn sample_account() -> AccountId {
    let public_key = PublicKey::from_str(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774",
    )
    .expect("sample public key parses");
    AccountId::new(public_key)
}
fn wsv_host() -> WsvHost {
    WsvHost::new_with_subject(MockWorldStateView::new(), sample_account())
}
fn assert_not_unknown_syscall(result: Result<u64, VMError>, host_name: &str, number: u32) {
    if let Err(error) = result
        && let VMError::UnknownSyscall(actual) = error.as_unmetered()
    {
        panic!("{host_name} returned UnknownSyscall({actual:#x}) for ABI v1 syscall {number:#x}");
    }
}
fn assert_host_covers_abi<H>(host_name: &str, make_host: impl Fn() -> H)
where
    H: IVMHost,
{
    let mut vm = IVM::new(u64::MAX);
    for &number in syscalls::abi_syscall_list() {
        let mut host = make_host();
        for reg in 10..=15 {
            vm.set_register(reg, 0);
        }
        let result = host.syscall(number, &mut vm);
        assert_not_unknown_syscall(result, host_name, number);
    }
    for number in [
        syscalls::SYSCALL_JSON_BUILD,
        syscalls::SYSCALL_STATE_VALUE_ENCODE,
        syscalls::SYSCALL_STATE_VALUE_DECODE,
        syscalls::SYSCALL_GET_PUBLIC_INPUT,
    ] {
        let spec = host_syscall_metering_spec(ivm::SyscallPolicy::AbiV1, number)
            .expect("registered reserve formula");
        assert_eq!(spec.formula, HostSyscallGasFormula::ReserveAvailable);
        assert_eq!(
            spec.quote_strategy,
            HostSyscallQuoteStrategy::ReserveAvailable
        );
    }
}
fn assert_prepare_covers_abi<H>(host_name: &str, make_host: impl Fn() -> H)
where
    H: IVMHost,
{
    let vm = IVM::new(u64::MAX);
    for &number in syscalls::abi_syscall_list() {
        let host = make_host();
        assert_not_unknown_syscall(host.prepare_syscall(number, &vm), host_name, number);
    }
}
fn assert_fastpq_scope_gas<H>(mut host: H)
where
    H: IVMHost,
{
    let mut vm = IVM::new(u64::MAX);
    assert_eq!(
        (host.syscall(syscalls::SYSCALL_TRANSFER_V1_BATCH_BEGIN, &mut vm))
            .expect("expected successful fixture result"),
        gas::G_FASTPQ_BATCH
    );
    let error = host
        .syscall(syscalls::SYSCALL_TRANSFER_V1_BATCH_END, &mut vm)
        .expect_err("empty FastPQ batch is rejected after fixed scope gas");
    assert_eq!(error.metered_gas(), Some(gas::G_FASTPQ_BATCH));
    assert!(matches!(error.as_unmetered(), VMError::DecodeError));
}
fn bytes_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    envelope.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test payload fits u32")
            .to_be_bytes(),
    );
    envelope.extend_from_slice(payload);
    envelope.extend_from_slice(Hash::new(payload).as_ref());
    envelope
}
fn assert_normalize_norito_bytes_conformance<H>(mut make_host: impl FnMut() -> H)
where
    H: IVMHost,
{
    const PAYLOAD: &[u8] = b"same bytes, canonical carrier";
    for source_type in [PointerType::Blob, PointerType::NoritoBytes] {
        let mut vm = IVM::new(u64::MAX);
        let source = vm
            .alloc_input_tlv(&bytes_tlv(source_type, PAYLOAD))
            .expect("install valid source TLV");
        vm.set_register(10, source);
        let mut host = make_host();
        let quote = host
            .prepare_syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &vm)
            .expect("normalization quote");
        let gas = host
            .syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &mut vm)
            .expect("normalize valid byte carrier");
        assert_eq!(gas, quote);
        let normalized = vm.register(10);
        assert_ne!(
            normalized, source,
            "normalization must allocate a fresh TLV"
        );
        let tlv = vm
            .validate_tlv(normalized)
            .expect("validate normalized TLV");
        assert_eq!(tlv.type_id, PointerType::NoritoBytes);
        assert_eq!(tlv.version, 1);
        assert_eq!(tlv.payload, PAYLOAD);
    }
    for invalid in [None, Some(PointerType::Name)] {
        let mut vm = IVM::new(u64::MAX);
        if let Some(pointer_type) = invalid {
            let pointer = vm
                .alloc_input_tlv(&bytes_tlv(pointer_type, b"wrong carrier"))
                .expect("install wrong-type TLV");
            vm.set_register(10, pointer);
        }
        let mut host = make_host();
        assert!(matches!(
            host.prepare_syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &vm),
            Err(VMError::NoritoInvalid)
        ));
        assert!(matches!(
            host.syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &mut vm),
            Err(VMError::NoritoInvalid)
        ));
    }
    let mut vm = IVM::new(u64::MAX);
    let mut malformed = bytes_tlv(PointerType::Blob, b"corrupt digest");
    *malformed.last_mut().expect("digest byte") ^= 1;
    let malformed = vm
        .alloc_input_tlv(&malformed)
        .expect("install malformed TLV bytes");
    vm.set_register(10, malformed);
    let mut host = make_host();
    assert_eq!(
        (host.prepare_syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &vm))
            .expect("expected successful fixture result"),
        gas::HOST_BYTE_GAS_BASE.saturating_add(
            gas::SYSCALL_GAS_PER_BYTE.saturating_mul(b"corrupt digest".len() as u64)
        )
    );
    assert!(
        host.syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &mut vm)
            .is_err()
    );
    let mut vm = IVM::new(u64::MAX);
    let unowned_stack = bytes_tlv(PointerType::Blob, b"unowned stack bytes");
    vm.store_bytes(ivm::Memory::STACK_START, &unowned_stack)
        .expect("store unowned stack TLV bytes");
    vm.set_register(10, ivm::Memory::STACK_START);
    let mut host = make_host();
    assert!(matches!(
        host.prepare_syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &vm),
        Err(VMError::NoritoInvalid)
    ));
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES, &mut vm),
        Err(VMError::NoritoInvalid)
    ));
}
#[test]
fn abi_v1_allowed_syscalls_are_covered_by_lightweight_hosts() {
    assert_host_covers_abi("DefaultHost", DefaultHost::new);
    assert_host_covers_abi("CoreHost", CoreHost::new);
    assert_host_covers_abi("WsvHost", wsv_host);
}
#[test]
fn abi_v1_allowed_syscalls_have_one_exhaustive_host_metering_registry() {
    let registry = abi_v1_host_syscall_metering_registry();
    let registered_numbers: Vec<_> = registry.iter().map(|spec| spec.number).collect();
    assert_eq!(registered_numbers, syscalls::abi_syscall_list());
    assert!(
        registry
            .windows(2)
            .all(|pair| pair[0].number < pair[1].number),
        "host metering registry must be sorted and deduplicated"
    );
    assert!(
        syscalls::abi_syscall_list()
            .iter()
            .all(|&number| syscalls::registered_syscall_access(number).is_some()),
        "every allowed syscall must have explicit access metadata"
    );
    assert!(
        syscalls::abi_syscall_list()
            .iter()
            .all(|&number| registered_host_syscall_gas_formula(number).is_some()),
        "every allowed syscall must have an explicit gas formula"
    );
    for class in [
        HostSyscallGasClass::VmLocal,
        HostSyscallGasClass::Allocation,
        HostSyscallGasClass::DurableStateRead,
        HostSyscallGasClass::DurableStateWrite,
        HostSyscallGasClass::LedgerRead,
        HostSyscallGasClass::LedgerWrite,
        HostSyscallGasClass::Dynamic,
    ] {
        assert!(
            registry.iter().any(|spec| spec.gas_class == class),
            "ABI-v1 registry is missing the {class:?} work class"
        );
    }
    let unknown = 0x00ff_fffe;
    assert!(!syscalls::is_syscall_allowed(
        ivm::SyscallPolicy::AbiV1,
        unknown
    ));
    assert_eq!(
        host_syscall_metering_spec(ivm::SyscallPolicy::AbiV1, unknown),
        None,
        "unknown numbers must not inherit a generic metering class"
    );
    assert_eq!(
        registered_host_syscall_gas_formula(unknown),
        None,
        "unknown numbers must not inherit a formula from their access class"
    );
    for &number in syscalls::abi_syscall_list() {
        let spec = host_syscall_metering_spec(ivm::SyscallPolicy::AbiV1, number)
            .expect("allowed syscall has metering metadata");
        let expected = if syscalls::is_numeric_v1_syscall(number) {
            SyscallMetering::Staged
        } else {
            SyscallMetering::Reserved
        };
        assert_eq!(spec.metering, expected, "metering mode for {number:#x}");
    }
}
#[test]
fn ledger_query_syscalls_use_the_descriptor_bound_v1_formula() {
    for number in [
        syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY,
        syscalls::SYSCALL_QUERY_EXECUTE_NORITO,
        syscalls::SYSCALL_CORE_QUERY_GET,
        syscalls::SYSCALL_CORE_QUERY_PAGE,
        syscalls::SYSCALL_QUERY_GET_PARAMETER,
        syscalls::SYSCALL_QUERY_GET_CONTRACT_MANIFEST,
        syscalls::SYSCALL_QUERY_GET_CONTRACT_INSTANCE,
        syscalls::SYSCALL_GET_ACCOUNT_BALANCE,
        syscalls::SYSCALL_RESOLVE_ACCOUNT_ALIAS,
    ] {
        let spec = host_syscall_metering_spec(ivm::SyscallPolicy::AbiV1, number)
            .expect("ledger-query syscall has metering metadata");
        assert_eq!(spec.formula, HostSyscallGasFormula::LedgerQueryV1);
        assert_eq!(spec.parameters, HostSyscallGasParameters::LedgerQueryV1);
        assert_eq!(
            spec.quote_strategy,
            HostSyscallQuoteStrategy::ReserveAvailable
        );
        assert_eq!(
            spec.minimum_gas,
            gas::LEDGER_QUERY_GAS_BASE_SINGULAR,
            "minimum gas for ledger-query syscall {number:#x}"
        );
    }
}
#[test]
fn abi_v1_prepare_paths_never_treat_an_allowed_syscall_as_unclassified() {
    assert_prepare_covers_abi("DefaultHost", DefaultHost::new);
    assert_prepare_covers_abi("CoreHost", CoreHost::new);
    assert_prepare_covers_abi("WsvHost", wsv_host);
}
#[test]
fn fastpq_batch_scope_syscalls_charge_fixed_gas_in_all_hosts() {
    assert_fastpq_scope_gas(DefaultHost::new());
    assert_fastpq_scope_gas(CoreHost::new());
    assert_fastpq_scope_gas(wsv_host());
}
#[test]
fn normalize_norito_bytes_is_identical_across_lightweight_hosts() {
    assert_normalize_norito_bytes_conformance(DefaultHost::new);
    assert_normalize_norito_bytes_conformance(CoreHost::new);
    assert_normalize_norito_bytes_conformance(wsv_host);
    assert!(syscalls::is_syscall_allowed(
        ivm::SyscallPolicy::AbiV1,
        syscalls::SYSCALL_NORMALIZE_NORITO_BYTES
    ));
    assert_eq!(
        syscalls::registered_syscall_access(syscalls::SYSCALL_NORMALIZE_NORITO_BYTES),
        Some(syscalls::SyscallAccess::None)
    );
    let spec = host_syscall_metering_spec(
        ivm::SyscallPolicy::AbiV1,
        syscalls::SYSCALL_NORMALIZE_NORITO_BYTES,
    )
    .expect("normalization metering spec");
    assert_eq!(spec.formula, HostSyscallGasFormula::ByteLinear);
    assert_eq!(
        spec.quote_strategy,
        HostSyscallQuoteStrategy::InputOutputBounded
    );
}

#[test]
fn state_get_metering_reserves_available_gas_and_retains_its_exact_formula() {
    let spec = host_syscall_metering_spec(ivm::SyscallPolicy::AbiV1, syscalls::SYSCALL_STATE_GET)
        .expect("STATE_GET metering spec");
    assert_eq!(spec.metering, SyscallMetering::Reserved);
    assert_eq!(spec.formula, HostSyscallGasFormula::StateGet);
    assert_eq!(spec.parameters, HostSyscallGasParameters::DurableState);
    assert_eq!(
        spec.quote_strategy,
        HostSyscallQuoteStrategy::ReserveAvailable
    );
    assert_eq!(spec.minimum_gas, gas::STATE_QUERY_GAS_BASE);
}
