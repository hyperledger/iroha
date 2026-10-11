//! Generic bytecode and hosts cannot acquire the operation-specific ballot/tally bridge.
#![cfg(feature = "zk-tests")]
use iroha_core::smartcontracts::ivm::host::CoreHost;
use iroha_data_model::{
    isi::{
        InstructionBox,
        zk::{FinalizeElection, SubmitBallot},
    },
    proof::{ProofAttachment, ProofBox, VerifyingKeyId},
};
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, IVMHost, PointerType, ProgramMetadata, encoding, instruction, syscalls};

fn attachment() -> ProofAttachment {
    ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        ProofBox::new("pipa-r/pasta".into(), vec![0xAB; 32]),
        VerifyingKeyId::new("pipa-r/pasta", "fixture"),
    )
}
fn assert_generic_bridge_rejected(instruction: InstructionBox) {
    let mut program = ProgramMetadata::default().encode();
    program.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            u8::try_from(syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION).unwrap(),
        )
        .to_le_bytes(),
    );
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(10_000_000);
    let expected = ivm::VMError::GenericSyscallNotAllowed {
        syscall: syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
    };
    assert_eq!(vm.load_program(&program), Err(expected.clone()));
    let payload = norito::to_bytes(&instruction).unwrap();
    let mut tlv = Vec::new();
    tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    tlv.extend_from_slice(&payload);
    tlv.extend_from_slice(iroha_crypto::Hash::new(&payload).as_ref());
    let pointer = vm.alloc_input_tlv(&tlv).unwrap();
    vm.set_register(10, pointer);
    vm.set_register(11, syscalls::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT);
    let mut host = CoreHost::new(ALICE_ID.clone());
    assert_eq!(
        host.syscall(syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION, &mut vm),
        Err(expected)
    );
    assert_eq!(vm.register(10), pointer);
}
#[test]
fn generic_submit_ballot_without_verify_is_rejected() {
    assert_generic_bridge_rejected(
        SubmitBallot {
            election_id: "election1".into(),
            ciphertext: vec![0; 32],
            ballot_proof: attachment(),
            nullifier: [1; 32],
        }
        .into(),
    );
}
#[test]
fn generic_finalize_election_without_verify_is_rejected() {
    assert_generic_bridge_rejected(
        FinalizeElection {
            election_id: "election1".into(),
            tally: vec![1, 0, 0],
            tally_proof: attachment(),
        }
        .into(),
    );
}
