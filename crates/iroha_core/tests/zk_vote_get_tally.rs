//! `CoreHost` test for `ZK_VOTE_GET_TALLY`: ensure it returns finalized and tally from snapshot.

#![cfg(feature = "zk-tests")]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::CoreHost,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::prelude::*;
use ivm::{IVMHost, Memory, PointerType, syscalls, zk_verify};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    let payload_len = u32::try_from(payload.len()).expect("payload length fits u32");
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(payload);
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn checked_random_zk_vote_tally_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked zk vote tally keypair")
}
fn checked_random_zk_vote_tally_account_id() -> AccountId {
    AccountId::new(checked_random_zk_vote_tally_keypair().public_key().clone())
}
#[test]
fn zk_vote_tally_fixture_uses_checked_randomness() {
    let key_pair = checked_random_zk_vote_tally_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::Ed25519);
}
#[test]
#[allow(clippy::too_many_lines)]
fn zk_vote_get_tally_roundtrip_from_snapshot() {
    // Build minimal state
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let owner = checked_random_zk_vote_tally_account_id();
    let account = Account::new(owner.clone()).build(&owner);
    let state = State::new_for_testing(World::with([], [account], []), kura, query);
    // Begin block and transaction
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    // A typed readback fixture, not a proof-admitted or consensus-finalized election.
    // The actual semantic tally verifier is unavailable; this syscall only reads state.
    let election_id = "e1".to_string();
    stx.world.elections_mut().insert(
        election_id.clone(),
        iroha_core::state::ElectionState {
            options: 2,
            finalized: true,
            tally: vec![4, 0],
            ..Default::default()
        },
    );
    stx.apply();
    // Snapshot elections into CoreHost and query via syscall
    let mut vm = ivm::IVM::new(1_000_000);
    let mut host = CoreHost::new(owner.clone());
    {
        use std::collections::BTreeMap;
        let mut esnap: BTreeMap<String, (u32, bool, Vec<u128>)> = BTreeMap::new();
        let e = block.world.elections().get(&election_id).unwrap();
        esnap.insert(
            election_id.clone(),
            (e.options, e.finalized, e.tally.clone()),
        );
        host.set_zk_elections_snapshot(esnap)
            .expect("valid election snapshot");
    }
    // Rejected malformed replacement must preserve the exact valid state snapshot.
    assert!(matches!(
        host.set_zk_elections_snapshot(std::collections::BTreeMap::from([(
            election_id.clone(),
            (2, true, Vec::new()),
        )])),
        Err(ivm::VMError::NoritoInvalid)
    ));
    // Build request TLV and call syscall
    let req = zk_verify::VoteGetTallyRequest { election_id };
    let payload = norito::to_bytes(&req).expect("encode req");
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    host.syscall(syscalls::SYSCALL_ZK_VOTE_GET_TALLY, &mut vm)
        .expect("syscall ok");
    let ptr = vm.register(10);
    let tlv_out = vm.memory.validate_tlv(ptr).expect("valid tlv");
    assert_eq!(tlv_out.type_id, PointerType::NoritoBytes);
    let resp: zk_verify::VoteGetTallyResponse =
        norito::decode_from_bytes(tlv_out.payload).expect("decode resp");
    assert!(resp.finalized);
    assert_eq!(resp.tally, vec![4, 0]);
}
