//! Rejection coverage for the retired JSON A0 administration envelope.
use iroha_crypto::Hash;
use iroha_primitives::json::Json;
use ivm::{
    IVM, IVMHost, PointerType, VMError,
    mock_wsv::{AccountId, MockWorldStateView, WsvHost},
    syscalls,
};
use ivm_abi::codec::encode_canonical_norito;
fn make_tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    let hash: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&hash);
    out
}
#[test]
fn json_admin_envelopes_are_rejected_for_every_a0_tag_without_mutation() {
    let caller = AccountId::new(
        "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
            .parse()
            .expect("public key"),
    );
    let mut host = WsvHost::new_with_subject(MockWorldStateView::new(), caller);
    let mut vm = IVM::new(u64::MAX);
    let envelope =
        Json::from_str_norito(r#"{"payload":{"name":"legacy"},"type":"wsv.create_trigger"}"#)
            .expect("JSON envelope");
    let payload = encode_canonical_norito(&envelope).expect("canonical Json");
    let pointer = vm
        .alloc_input_tlv(&make_tlv(PointerType::Json, &payload))
        .expect("allocate JSON envelope");
    vm.set_register(10, pointer);
    // Tag 2 was the retired contract-originated SCCP send and is an unknown tag now.
    for tag in [
        0,
        syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT,
        2,
        99,
    ] {
        vm.set_register(11, tag);
        assert!(
            matches!(
                host.syscall(syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION, &mut vm),
                Err(VMError::NoritoInvalid)
            ),
            "JSON pointer must be rejected before interpreting tag {tag}"
        );
    }
    assert_eq!(host.wsv.trigger_state("legacy"), None);
}
