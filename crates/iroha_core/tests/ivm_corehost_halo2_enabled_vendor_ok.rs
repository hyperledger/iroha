#![doc = "Positive gating path: with Halo2 enabled and within `max_k`, a prior\n`ZK_VOTE_VERIFY_BALLOT` sets the `CoreHost` latch and allows enqueued\n`SubmitBallot` (via vendor bridge) to apply."]
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
#![cfg(feature = "zk-ipa-native")]
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
use iroha_config::parameters::defaults;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::{Execute, ivm::host::CoreHost},
    state::State,
};
use iroha_core_zk::test_utils::halo2_fixture_envelope;
use iroha_data_model::{
    confidential::ConfidentialStatus,
    isi::verifying_keys,
    prelude::*,
    proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
use iroha_executor_data_model::permission::governance::{
    CanManageParliament, CanSubmitGovernanceBallot,
};
use iroha_primitives::json::Json;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, PointerType, ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use nonzero_ext::nonzero;
use sha2::{Digest, Sha256};
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
fn verify_then_vendor_submit_ballot_applies() {
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
    // halo2 verification is enabled here (in addition to the host-local halo2 config used by
    // the syscall verifier).
    state
        .edit_zk_for_testing(|zk| zk.halo2.enabled = true)
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
    // Authority and VM/host configured for Halo2 IPA (ToyP61), max_k >= 8
    let mut vm = IVM::new(1_000_000);
    let mut host = CoreHost::with_accounts(authority.clone(), Arc::new(vec![authority.clone()]));
    let chain_id_bytes = state.chain_id.to_string().into_bytes();
    host.set_chain_id_bytes(chain_id_bytes.clone());
    let backend_label = "halo2/ipa";
    let circuit_id = "halo2/ipa:tiny-add2inst-public";
    let fixture_seed = halo2_fixture_envelope(circuit_id, [0u8; 32]);
    let vk_bytes = fixture_seed.vk_bytes.clone().expect("fixture vk bytes");
    let mut hasher = Sha256::new();
    hasher.update(backend_label.as_bytes());
    hasher.update(&vk_bytes);
    let vk_commitment: [u8; 32] = hasher.finalize().into();
    let fixture = halo2_fixture_envelope(circuit_id, vk_commitment);
    let schema_hash = fixture.schema_hash;
    let mut vk_record = VerifyingKeyRecord::new_with_owner(
        1,
        circuit_id,
        None,
        "ballot",
        BackendTag::Halo2IpaPasta,
        "pallas",
        schema_hash,
        vk_commitment,
    );
    vk_record.status = ConfidentialStatus::Active;
    vk_record.key = Some(VerifyingKeyBox::new(backend_label.into(), vk_bytes.clone()));
    vk_record.vk_len = u32::try_from(vk_bytes.len()).expect("vk length fits in u32");
    vk_record.max_proof_bytes = u32::MAX;
    vk_record.gas_schedule_id = Some("halo2_default".into());
    let vk_record_for_state = vk_record.clone();
    let mut vk_map = BTreeMap::new();
    vk_map.insert(VerifyingKeyId::new(backend_label, "vk_ballot"), vk_record);
    host.set_verifying_keys(vk_map).expect("set registry");
    host.set_halo2_config(&iroha_config::parameters::actual::Halo2 {
        enabled: true,
        curve: iroha_config::parameters::actual::ZkCurve::Pallas,
        backend: iroha_config::parameters::actual::Halo2Backend::Ipa,
        max_k: 18,
        verifier_budget_ms: 200,
        verifier_max_batch: 8,
        verifier_worker_threads: defaults::zk::halo2::VERIFIER_WORKER_THREADS,
        verifier_queue_cap: defaults::zk::halo2::VERIFIER_QUEUE_CAP,
        verifier_enqueue_wait_ms: defaults::zk::halo2::VERIFIER_ENQUEUE_WAIT_MS,
        verifier_retry_ring_cap: defaults::zk::halo2::VERIFIER_RETRY_RING_CAP,
        verifier_retry_max_attempts: defaults::zk::halo2::VERIFIER_RETRY_MAX_ATTEMPTS,
        verifier_retry_tick_ms: defaults::zk::halo2::VERIFIER_RETRY_TICK_MS,
        max_envelope_bytes: defaults::zk::halo2::MAX_ENVELOPE_BYTES,
        max_proof_bytes: usize::MAX,
        max_transcript_label_len: defaults::zk::halo2::MAX_TRANSCRIPT_LABEL_LEN,
        enforce_transcript_label_ascii: defaults::zk::halo2::ENFORCE_TRANSCRIPT_LABEL_ASCII,
    });
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
    let vk_ballot = VerifyingKeyId::new("halo2/ipa", "vk_ballot");
    let vk_tally = vk_ballot.clone();
    verifying_keys::RegisterVerifyingKey {
        id: vk_ballot.clone(),
        record: vk_record_for_state.clone(),
    }
    .execute(&authority, &mut stx)
    .expect("register ballot vk");
    // 1) Verify ballot: prepare envelope TLV in INPUT and run SCALL
    let env_bytes = fixture.proof_bytes.clone();
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &env_bytes);
    let mut cursor = 0;
    let ptr = store_tlv(&mut vm, &mut cursor, &tlv);
    vm.set_register(10, ptr);
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_sys(
            instruction::wide::system::SCALL,
            ivm_sys::SYSCALL_ZK_VOTE_VERIFY_BALLOT as u8,
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
    // Seed an election so SubmitBallot can record an ordered ballot pair.
    let mut commit_bytes = [0u8; 32];
    let mut root_bytes = [0u8; 32];
    commit_bytes.copy_from_slice(&fixture.public_inputs[..32]);
    root_bytes.copy_from_slice(&fixture.public_inputs[32..64]);
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
    create
        .execute(&authority, &mut stx)
        .expect("create election in WSV");
    // 2) Enqueue SubmitBallot via the vendor bridge
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
            "halo2/ipa".into(),
            fixture.proof_box("halo2/ipa"),
            vk_ballot.clone(),
        ),
        nullifier,
    };
    let sb_box: iroha_data_model::isi::InstructionBox = sb.into();
    let sb_bytes = norito::to_bytes(&sb_box).expect("encode SubmitBallot InstructionBox to Norito");
    let tlv2 = make_tlv(PointerType::NoritoBytes as u16, &sb_bytes);
    let ptr2 = store_tlv(&mut vm, &mut cursor, &tlv2);
    vm.set_register(10, ptr2);
    vm.load_program(&prog2).expect("load vendor2");
    vm.run().expect("run vendor2");
    // 3) Apply queued instructions; should succeed thanks to verify latch
    CoreHost::with_host(&mut vm, |host| host.apply_queued(&mut stx, &authority))
        .expect("apply queued after verify");
}
