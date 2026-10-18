use crate::common;
use iroha_crypto::Hash;
use ivm::{IVM, Memory, PointerType};
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let payload = PointerType::from_u16(type_id)
        .map(|pty| common::payload_for_type(pty, payload))
        .unwrap_or_else(|| payload.to_vec());
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload.as_ref());
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
#[test]
fn input_tlv_bump_allocator_places_entries_without_overlap() {
    let mut vm = IVM::new(10);
    let hdr = ivm::ProgramMetadata::default().encode();
    vm.load_program(&hdr).unwrap();
    let t1 = make_tlv(PointerType::Name as u16, b"k1");
    let t2 = make_tlv(PointerType::Json as u16, br#"{"a":1}"#);
    let p1 = vm.alloc_input_tlv(&t1).expect("alloc1");
    let p2 = vm.alloc_input_tlv(&t2).expect("alloc2");
    assert!(p2 > p1);
    // Ensure 8-byte alignment for published TLVs
    assert_eq!(p1 % 8, 0, "p1 must be 8-byte aligned");
    assert_eq!(p2 % 8, 0, "p2 must be 8-byte aligned");
    // Validate both TLVs via Norito check and INPUT bounds
    assert!((Memory::INPUT_START..Memory::INPUT_START + Memory::INPUT_SIZE).contains(&p1));
    assert!((Memory::INPUT_START..Memory::INPUT_START + Memory::INPUT_SIZE).contains(&p2));
    vm.memory.validate_tlv(p1).expect("tlv1 valid");
    vm.memory.validate_tlv(p2).expect("tlv2 valid");
}
#[test]
fn input_region_is_cleared_between_vms() {
    let hdr = ivm::ProgramMetadata::default().encode();
    let mut vm1 = IVM::new(10);
    vm1.load_program(&hdr).unwrap();
    let tlv = make_tlv(PointerType::Blob as u16, b"secret-bytes");
    vm1.alloc_input_tlv(&tlv).expect("alloc leak tlv");
    drop(vm1);
    let mut vm2 = IVM::new(10);
    vm2.load_program(&hdr).unwrap();
    let snapshot = vm2
        .memory
        .load_region(Memory::INPUT_START, tlv.len() as u64)
        .expect("read fresh input");
    assert!(
        snapshot.iter().all(|&b| b == 0),
        "INPUT region should start zeroed"
    );
}
