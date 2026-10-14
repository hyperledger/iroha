#![doc = "End-to-end vendor bridge gating path for ZK verification"]
#![cfg(feature = "zk-tests")]
//! An injected verification latch cannot authorize an unadmitted native proof relation.
//!
//! A real native transfer proof relabelled as a ballot remains inadmissible even if a test-only helper
//! forces the prior-verification latch. Initial executor authority and the direct
//! relation-role consumer are checked separately; the latter is an instruction
//! unit boundary, not a successful production host handoff.
#[path = "common/native_genesis.rs"]
mod native_genesis;
use iroha_core::smartcontracts::Execute;
use iroha_core::{smartcontracts::ivm::host::CoreHost, state::WorldReadOnly};
use iroha_crypto::Hash;
use iroha_data_model::{
    account::Account,
    asset::AssetDefinition,
    domain::Domain,
    isi::smart_contract_code::{
        ActivateContractInstance, RegisterSmartContractBytes, RegisterSmartContractCode,
    },
    permission::Permission,
    prelude::*,
};
use iroha_executor_data_model::permission::governance::{
    CanManageParliament, CanSubmitGovernanceBallot,
};
use iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::json::Json;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use ivm::{IVM, PointerType, host::IVMHost, syscalls as ivm_sys};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::sync::Arc;
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    let h: [u8; 32] = Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
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
#[allow(clippy::too_many_lines)]
fn forced_vendor_latch_cannot_admit_development_ballot() {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    // Minimal state
    let authority: AccountId = ALICE_ID.clone();
    let domain_id: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain");
    let domain = Domain::new(domain_id.clone()).build(&authority);
    let account = Account::new(authority.clone()).build(&authority);
    let world = iroha_core::state::World::with([domain], [account], Vec::<AssetDefinition>::new());
    let mut state = native_genesis::certified_state(world);
    state.gov.citizenship_bond_amount = 0_u64.into();
    state
        .edit_zk_for_testing(|zk| zk.pipa_r.enabled = true)
        .expect("fixture ZK settings install");
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // Authority and host
    let mut vm = IVM::new(10_000_000);
    let mut host = CoreHost::with_accounts(authority.clone(), Arc::new(vec![authority.clone()]));
    let ballot_bundle = super::zk_testkit::unqualified_native_ballot_bundle();
    let vk_commitment = ballot_bundle.vk_record.commitment;
    let vk_id = ballot_bundle.vk_id.clone();
    let vk_record = ballot_bundle.vk_record.clone();
    let perm_vk = Permission::new("CanManageVerifyingKeys".to_string(), Json::new(()));
    let perm_parliament: Permission = CanManageParliament.into();
    let perm_submit: Permission = CanSubmitGovernanceBallot {
        referendum_id: "election1".to_string(),
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
    let contract_call_permission =
        Permission::new("CanUseVendorBridgeTest".to_owned(), Json::new(()));
    Grant::account_permission(contract_call_permission, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant vendor-bridge contract permission");
    let lifecycle_permission: Permission = CanManageSmartContractCode.into();
    Grant::account_permission(lifecycle_permission, authority.clone())
        .execute(&authority, &mut stx)
        .expect("grant contract lifecycle permission");
    let (contract_program, _) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            r#"
seiyaku VendorBridgeGate { permission CanUseVendorBridgeTest;
    kotoage fn execute(bytes instruction) authorize(CanUseVendorBridgeTest) {
        ledger::governance::submit_ballot(value: instruction);
    }
}
"#,
        )
        .expect("compile admitted vendor-bridge contract");
    let verified_contract =
        ivm::verify_contract_artifact(&contract_program).expect("verify vendor-bridge contract");
    let contract_code_hash = verified_contract.code_hash;
    RegisterSmartContractBytes {
        artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            contract_code_hash,
        ),
        code: contract_program.clone(),
    }
    .execute(&authority, &mut stx)
    .expect("register vendor-bridge contract bytes");
    {
        let scoped_manifest = verified_contract
            .manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &ALICE_KEYPAIR,
            )
            .expect("sign bounded fixture manifest");
        RegisterSmartContractCode {
            artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                scoped_manifest
                    .code_hash
                    .unwrap_or_else(|| iroha_crypto::Hash::new(b"missing test manifest hash")),
            ),
            manifest: scoped_manifest,
        }
    }
    .execute(&authority, &mut stx)
    .expect("register vendor-bridge contract manifest");
    let contract_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &authority,
        0,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive vendor-bridge contract address");
    Register::account(Account::new(contract_address.subject_id()))
        .execute(&authority, &mut stx)
        .expect("register vendor-bridge contract subject");
    let contract_submit_permission: Permission = CanSubmitGovernanceBallot {
        referendum_id: "election1".to_owned(),
    }
    .into();
    Grant::account_permission(contract_submit_permission, contract_address.subject_id())
        .execute(&authority, &mut stx)
        .expect("grant ballot submission to the contract effect authority");
    stx.world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), authority.clone());
    ActivateContractInstance {
        contract_address: contract_address.clone(),
        expected_revision: 1,
        code_hash: contract_code_hash,
    }
    .execute(&authority, &mut stx)
    .expect("activate vendor-bridge contract");
    let prepared_contract = ivm::prepare_contract(Arc::<[u8]>::from(contract_program))
        .expect("prepare vendor-bridge contract");
    host.bind_authorized_deployed_contract_runtime_context(
        &stx,
        &contract_address,
        None,
        &prepared_contract,
        "execute",
    )
    .expect("bind admitted vendor-bridge contract");
    // Corrupt retained state, never a successfully registered production key.
    stx.world
        .verifying_keys_mut_for_testing()
        .insert(vk_id.clone(), vk_record);
    let commit_bytes = ballot_bundle.commit_bytes();
    let root_bytes = ballot_bundle.root_bytes();
    // Seed an invalid retained election to test the vendor latch boundary.
    stx.world.elections_mut().insert(
        "election1".to_owned(),
        iroha_core::state::ElectionState {
            options: 2,
            eligible_root: root_bytes,
            start_ts: 0,
            end_ts: 10_000,
            finalized: false,
            tally: vec![0, 0],
            accepted_ballots: Vec::new(),
            vk_ballot: Some(vk_id.clone()),
            vk_ballot_commitment: Some(vk_commitment),
            vk_tally: Some(vk_id.clone()),
            vk_tally_commitment: Some(vk_commitment),
            domain_tag: "zkvote".to_owned(),
        },
    );
    // Build a well-formed SubmitBallot carrying an unqualified development relation.
    let nullifier =
        derive_ballot_nullifier("zkvote", &state.network_id, "election1", &commit_bytes);
    let sb = iroha_data_model::isi::zk::SubmitBallot {
        election_id: "election1".to_string(),
        ciphertext: commit_bytes.to_vec(),
        ballot_proof: iroha_data_model::proof::ProofAttachment::new_ref(
            ballot_bundle.backend.into(),
            iroha_data_model::proof::ProofBox::new(
                ballot_bundle.backend.into(),
                ballot_bundle.proof_bytes.clone(),
            ),
            vk_id.clone(),
        ),
        nullifier,
    };
    let sb_bytes = norito::to_bytes(&InstructionBox::from(sb.clone()))
        .expect("encode SubmitBallot instruction box to Norito");
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &sb_bytes);
    let mut cursor = 0;
    let ptr = store_tlv(&mut vm, &mut cursor, &tlv);
    vm.set_register(10, ptr);
    vm.set_register(11, ivm_sys::SMARTCONTRACT_INSTRUCTION_TAG_SUBMIT_BALLOT);
    // Run once — without verify flag, apply should be rejected
    let env_hash: [u8; 32] = Hash::new(&ballot_bundle.proof_bytes).into();
    host.syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION, &mut vm)
        .expect("queue ballot through the vendor bridge");
    let err = host
        .apply_queued(&mut stx, &authority)
        .expect_err("missing verify must reject");
    match err {
        iroha_data_model::ValidationFail::NotPermitted(msg) => {
            assert!(msg.contains("missing ZK_VOTE_VERIFY_BALLOT"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    // Seed ballot verification latch with the expected envelope hash to simulate
    // a prior successful `ZK_VOTE_VERIFY_BALLOT`.
    host.__test_seed_ballot_latch(env_hash);
    // A synthetic prior-verification latch cannot authorize the retired circuit.
    vm.set_register(10, ptr);
    host.syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION, &mut vm)
        .expect("requeue ballot through the vendor bridge");
    let error = host
        .apply_queued(&mut stx, &authority)
        .expect_err("forced latch must not bypass production circuit admission");
    // The host has consumed the exact one-shot verification latch, but its
    // contract context does not grant Initial executor admission to this ISI.
    // Retain that real barrier; do not allowlist a directly signed ballot.
    match error {
        iroha_data_model::ValidationFail::NotPermitted(message) => assert_eq!(
            message,
            format!(
                "Initial executor does not admit unclassified native instruction `{}`",
                InstructionBox::from(sb.clone()).id()
            ),
        ),
        other => panic!("unexpected forced-latch rejection: {other:?}"),
    }
    vm.set_register(10, ptr);
    host.syscall(ivm_sys::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION, &mut vm)
        .expect("requeue the original envelope without another verification");
    let error = host
        .apply_queued(&mut stx, &authority)
        .expect_err("failed executor admission cannot replenish the consumed latch");
    match error {
        iroha_data_model::ValidationFail::NotPermitted(message) => assert_eq!(
            message,
            "missing ZK_VOTE_VERIFY_BALLOT prior to SubmitBallot",
        ),
        other => panic!("unexpected consumed-latch rejection: {other:?}"),
    }
    // Exercise the retained relation-role assertion at its actual instruction
    // consumer. This direct unit call is not a production authority route.
    let error = sb
        .execute(&contract_address.subject_id(), &mut stx)
        .expect_err("development relation must fail the dedicated ballot circuit role");
    assert!(
        format!("{error:?}").contains("ballot verifying key circuit mismatch"),
        "unexpected direct ballot relation rejection: {error:?}"
    );
    let election = stx.world.elections().get("election1").unwrap();
    assert!(election.accepted_ballots.is_empty());
    assert!(stx.world.governance_locks().get("election1").is_none());
}
