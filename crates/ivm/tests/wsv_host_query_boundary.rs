//! Strict V1 `SMARTCONTRACT_EXECUTE_QUERY` request boundary in the mock WSV host.
use iroha_data_model::query::{QueryRequest, SingularQueryBox, executor::FindParameters};
use iroha_primitives::json::Json;
use ivm::{
    IVM, IVMHost, PointerType, VMError,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    syscalls,
};
use ivm_abi::codec::encode_canonical_norito;
fn sample_account() -> AccountId {
    AccountId::new(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("public key"),
    )
}
fn make_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + iroha_crypto::Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    let hash: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    out.extend_from_slice(&hash);
    out
}
fn execute_query(
    host: &mut WsvHost,
    vm: &mut IVM,
    pointer_type: PointerType,
    payload: &[u8],
) -> Result<u64, VMError> {
    let pointer = vm
        .alloc_input_tlv(&make_tlv(pointer_type, payload))
        .expect("allocate request TLV");
    vm.set_register(10, pointer);
    host.syscall(syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY, vm)
}
#[test]
fn canonical_query_request_is_validated_before_not_implemented() {
    let caller = sample_account();
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    let mut vm = IVM::new(u64::MAX);
    let request = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    let canonical = encode_canonical_norito(&request).expect("canonical QueryRequest");
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let ambient_guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    let probe = vec!["ambient".to_owned(), "layout".to_owned()];
    let before = norito::to_bytes(&probe).expect("encode ambient probe");
    assert!(
        matches!((&(execute_query(&mut host, &mut vm, PointerType::NoritoBytes, &canonical)), &(VMError::NotImplemented {
            syscall: syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_QUERY,
        })), (Err(VMError::NotImplemented { syscall: __actual_syscall }), VMError::NotImplemented { syscall: __expected_syscall }) if __actual_syscall == __expected_syscall)
    );
    assert_eq!(
        norito::to_bytes(&probe).expect("re-encode ambient probe"),
        before,
        "canonical decoding must restore ambient Norito flags"
    );
    drop(ambient_guard);
}
#[test]
fn alternate_wrong_nominal_wrong_pointer_and_malformed_queries_are_rejected() {
    let caller = sample_account();
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    let mut vm = IVM::new(u64::MAX);
    let request = QueryRequest::Singular(SingularQueryBox::FindParameters(FindParameters));
    let canonical = encode_canonical_norito(&request).expect("canonical QueryRequest");
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let alternate = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&request).expect("alternate-layout QueryRequest")
    };
    assert_ne!(alternate, canonical);
    assert!(matches!(
        execute_query(&mut host, &mut vm, PointerType::NoritoBytes, &alternate),
        Err(VMError::NoritoInvalid)
    ));
    let wrong_nominal = encode_canonical_norito(&Json::from(norito::json::Value::Object(
        norito::json::Map::new(),
    )))
    .expect("canonical wrong nominal value");
    assert!(matches!(
        execute_query(&mut host, &mut vm, PointerType::NoritoBytes, &wrong_nominal),
        Err(VMError::NoritoInvalid)
    ));
    assert!(matches!(
        execute_query(&mut host, &mut vm, PointerType::Json, &canonical),
        Err(VMError::NoritoInvalid)
    ));
    assert!(matches!(
        execute_query(&mut host, &mut vm, PointerType::NoritoBytes, &[0xFF]),
        Err(VMError::NoritoInvalid)
    ));
}
