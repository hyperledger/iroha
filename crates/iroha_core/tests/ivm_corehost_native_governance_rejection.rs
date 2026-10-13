//! Genuine native verification does not authorize a governance ballot through the vendor bridge.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::{Execute, ivm::host::CoreHost},
    state::{State, WorldReadOnly as _},
};
use iroha_core_zk::test_utils::native_confidential_fixture_envelope;
use iroha_data_model::{
    confidential::ConfidentialStatus,
    isi::verifying_keys,
    prelude::*,
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use iroha_executor_data_model::permission::governance::{
    CanManageParliament, CanSubmitGovernanceBallot,
};
use iroha_primitives::json::Json;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, PointerType, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use mv::storage::StorageReadOnly as _;
use nonzero_ext::nonzero;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(7 + payload.len() + 32);
    v.extend_from_slice(&type_id.to_be_bytes());
    v.push(1);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    v.extend_from_slice(&h);
    v
}
fn store_tlv(vm: &mut IVM, cursor: &mut u64, tlv: &[u8]) -> u64 {
    vm.memory
        .input_write_aligned(cursor, tlv, 8)
        .expect("write TLV into INPUT")
}
fn derive_ballot_nullifier(
    domain_tag: &str,
    network_id: &iroha_data_model::NetworkId,
    election_id: &str,
    commit: &[u8; 32],
) -> [u8; 32] {
    use blake2::{Blake2b512, Digest as _};
    fn push_len(buf: &mut Vec<u8>, len: usize) {
        let len_u64 = len as u64;
        buf.extend_from_slice(&len_u64.to_le_bytes());
    }
    let mut input = Vec::with_capacity(
        domain_tag.len() + network_id.as_bytes().len() + election_id.len() + commit.len() + 24,
    );
    push_len(&mut input, domain_tag.len());
    input.extend_from_slice(domain_tag.as_bytes());
    push_len(&mut input, network_id.as_bytes().len());
    input.extend_from_slice(network_id.as_bytes());
    push_len(&mut input, election_id.len());
    input.extend_from_slice(election_id.as_bytes());
    input.extend_from_slice(commit);
    let digest = Blake2b512::digest(&input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}
#[test]
fn generic_native_verification_cannot_authorize_vendor_ballot() {
    // Minimal node state
    let authority: AccountId = ALICE_ID.clone();
    let domain_id: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = iroha_core::state::World::with([domain], [account], Vec::<AssetDefinition>::new());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query);
    // Governance and ISI verification consult the node `Zk` config guardrails, so ensure
    // native verification is enabled here (in addition to the host-local native config used by
    // the syscall verifier).
    state
        .edit_zk_for_testing(|zk| zk.pipa_r.enabled = true)
        .expect("fixture ZK settings install");
    state
        .edit_zk_for_testing(|zk| zk.verify_timeout = Duration::ZERO)
        .expect("fixture ZK settings install");
    let mut gov_cfg = state.gov.clone();
    gov_cfg.citizenship_bond_amount = 0_u64.into();
    state.set_gov(gov_cfg);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // Authority and VM/host use the fixed native PIPA-R relation
    let mut vm = IVM::new(1_000_000);
    let mut host = CoreHost::with_accounts(authority.clone(), Arc::new(vec![authority.clone()]));
    let chain_id_bytes = state.chain_id.to_string().into_bytes();
    host.set_chain_id_bytes(chain_id_bytes.clone());
    let backend_label = "pipa-r/pasta";
    let circuit_id = iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
    let fixture = native_confidential_fixture_envelope();
    let vk_box = fixture.vk_box(backend_label).expect("actual native VK");
    let vk_bytes = vk_box.bytes.clone();
    let vk_commitment = iroha_core_zk::hash_vk(&vk_box);
    let schema_hash = fixture.schema_hash;
    let mut vk_record = VerifyingKeyRecord::new_with_owner(
        1,
        circuit_id,
        None,
        "ballot",
        BackendTag::NativePipaRPasta,
        "vesta",
        schema_hash,
        vk_commitment,
    );
    vk_record.status = ConfidentialStatus::Active;
    vk_record.key = Some(vk_box);
    vk_record.vk_len = u32::try_from(vk_bytes.len()).expect("vk length fits in u32");
    vk_record.max_proof_bytes = u32::MAX;
    vk_record.gas_schedule_id = Some("native_pipa_r_default".into());
    let vk_record_for_state = vk_record.clone();
    let mut vk_map = BTreeMap::new();
    vk_map.insert(VerifyingKeyId::new(backend_label, "vk_ballot"), vk_record);
    host.set_verifying_keys(vk_map).expect("set registry");
    host.set_zk_config(&state.zk_snapshot());
    vm.set_host(host);
    // Grant authority permissions and register verifying keys in the WSV for governance plumbing.
    let perm_vk = Permission::new("CanManageVerifyingKeys".to_string(), Json::new(()));
    let perm_parliament: Permission = CanManageParliament.into();
    let perm_submit: Permission = CanSubmitGovernanceBallot {
        referendum_id: "e1".to_string(),
    }
    .into();
    Grant::account_permission(perm_vk, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant vk permission");
    Grant::account_permission(perm_parliament, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant parliament permission");
    Grant::account_permission(perm_submit, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant submit ballot permission");
    let vk_ballot = VerifyingKeyId::new("pipa-r/pasta", "vk_ballot");
    let vk_tally = vk_ballot.clone();
    verifying_keys::RegisterVerifyingKey {
        id: vk_ballot.clone(),
        record: vk_record_for_state.clone(),
    }
    .execute(&authority, &mut stx)
    .expect("register ballot vk");
    // 1) Verify the genuine native proof through the generic proof syscall.
    let env_bytes = fixture.proof_bytes.clone();
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &env_bytes);
    let mut cursor = 0;
    let ptr = store_tlv(&mut vm, &mut cursor, &tlv);
    vm.set_register(10, ptr);
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            ivm_sys::SYSCALL_VERIFY_PROOF as u8,
        )
        .to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut prog = ProgramMetadata {
        vector_length: 4,
        ..ProgramMetadata::default()
    }
    .encode();
    prog.extend_from_slice(&code);
    vm.load_program(&prog).expect("load verify");
    vm.run().expect("run verify");
    let verify_res = vm.register(10);
    let verify_err = vm.register(11);
    assert_ne!(
        verify_res, 0,
        "verify must succeed under enabled config (err code {verify_err})"
    );
    // A genuine generic proof must not qualify a governance election.
    let commit_bytes = [0x31; 32];
    let root_bytes = [0x32; 32];
    let create = iroha_data_model::isi::zk::CreateElection {
        election_id: "e1".to_string(),
        options: 2,
        eligible_root: root_bytes,
        start_ts: 0,
        end_ts: 0,
        vk_ballot: vk_ballot.clone(),
        vk_tally,
        domain_tag: "zkvote".to_string(),
    };
    let error = create
        .execute(&authority, &mut stx)
        .expect_err("generic native proof must not create a governance election");
    assert!(
        format!("{error:?}").contains("not qualified")
            || format!("{error:?}").contains("circuit mismatch")
    );
    assert!(stx.world.elections().get(&"e1".to_owned()).is_none());
    // 2) Generic programs cannot enter the operation-specific contract bridge.
    let mut code2 = Vec::new();
    code2.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION as u8,
        )
        .to_le_bytes(),
    );
    code2.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut prog2 = ProgramMetadata {
        vector_length: 4,
        ..ProgramMetadata::default()
    }
    .encode();
    prog2.extend_from_slice(&code2);
    let nullifier = derive_ballot_nullifier("zkvote", &state.network_id, "e1", &commit_bytes);
    let sb = iroha_data_model::isi::zk::SubmitBallot {
        election_id: "e1".to_string(),
        ciphertext: commit_bytes.to_vec(),
        ballot_proof: iroha_data_model::proof::ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            fixture.proof_box("pipa-r/pasta"),
            vk_ballot.clone(),
        ),
        nullifier,
    };
    let sb_box: iroha_data_model::isi::InstructionBox = sb.into();
    let sb_bytes = norito::to_bytes(&sb_box).expect("encode SubmitBallot InstructionBox to Norito");
    let tlv2 = make_tlv(PointerType::NoritoBytes as u16, &sb_bytes);
    let ptr2 = store_tlv(&mut vm, &mut cursor, &tlv2);
    vm.set_register(10, ptr2);
    assert!(match (
        &(vm.load_program(&prog2)),
        &(ivm::VMError::GenericSyscallNotAllowed {
            syscall: ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
        })
    ) {
        (
            Err(ivm::VMError::GenericSyscallNotAllowed {
                syscall: actual_field_0,
            }),
            ivm::VMError::GenericSyscallNotAllowed {
                syscall: expected_field_0,
            },
        ) => actual_field_0 == expected_field_0,
        _ => false,
    });
    // Generic verification creates no queued instruction or governance authority.
    assert!(
        CoreHost::with_host(&mut vm, |host| host.apply_queued(&mut stx, &authority))
            .expect("empty generic effect queue")
            .is_empty()
    );
    assert!(stx.world.elections().get(&"e1".to_owned()).is_none());
}
