//! Tests for `ZK_ROOTS_GET` respecting request max and configured cap.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]
use iroha_config::parameters::{actual as cfg, defaults};
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::ivm::host::CoreHost,
    state::{State, World, WorldReadOnly},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{account::NewAccount, prelude::*};
use iroha_model_base::domain::DomainId;
use ivm::{IVMHost, Memory, PointerType, syscalls, zk_verify};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn make_tlv(type_id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + 32);
    out.extend_from_slice(&type_id.to_be_bytes());
    out.push(1);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    let h: [u8; 32] = iroha_crypto::Hash::new(payload).into();
    out.extend_from_slice(&h);
    out
}
fn checked_random_zk_roots_keypair() -> KeyPair {
    KeyPair::try_random().expect("generate checked zk roots keypair")
}
fn checked_random_zk_roots_account_id() -> AccountId {
    AccountId::new(checked_random_zk_roots_keypair().public_key().clone())
}
#[test]
fn zk_roots_get_fixture_uses_checked_randomness() {
    let key_pair = checked_random_zk_roots_keypair();
    assert_eq!(key_pair.public_key().algorithm(), Algorithm::Ed25519);
}
#[test]
fn zk_roots_get_respects_cap_and_max() {
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!("Skipping: zk roots get cap test gated. Set IROHA_RUN_IGNORED=1 to run.");
        return;
    }
    // Build state with small roots cap
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(World::new(), kura, query);
    state
        .set_zk(cfg::Zk {
            pipa_r: iroha_config::parameters::actual::PipaR::default(),
            trace: iroha_config::parameters::actual::DiagnosticTrace::default(),
            ipa_commitment: iroha_config::parameters::actual::IpaCommitment::default(),
            max_verify_batch: iroha_config::parameters::defaults::zk::MAX_VERIFY_BATCH,
            fastpq: cfg::Fastpq {
                execution_mode: cfg::FastpqExecutionMode::Cpu,
                poseidon_mode: cfg::FastpqPoseidonMode::Cpu,
                proof_sidecar_queue_cap: defaults::zk::fastpq::PROOF_SIDECAR_QUEUE_CAP,
                proof_sidecar_max_bytes: defaults::zk::fastpq::PROOF_SIDECAR_MAX_BYTES,
                proof_sidecar_max_retries: defaults::zk::fastpq::PROOF_SIDECAR_MAX_RETRIES,
                device_class: None,
                chip_family: None,
                gpu_kind: None,
                metal_queue_fanout: None,
                metal_queue_column_threshold: None,
                metal_max_in_flight: None,
                metal_threadgroup_width: None,
                metal_trace: defaults::zk::fastpq::METAL_TRACE,
                metal_debug_enum: defaults::zk::fastpq::METAL_DEBUG_ENUM,
            },
            stark: cfg::Stark::default(),
            sccp: cfg::Sccp::default(),
            ballot_history_cap: defaults::zk::vote::BALLOT_HISTORY_CAP,
            preverify_max_bytes: defaults::zk::preverify::MAX_BYTES,
            preverify_budget_bytes: defaults::zk::preverify::BUDGET_BYTES,
            proof_history_cap: defaults::zk::proof::RECORD_HISTORY_CAP,
            proof_retention_grace_blocks: defaults::zk::proof::RETENTION_GRACE_BLOCKS,
            proof_prune_batch: defaults::zk::proof::PRUNE_BATCH_SIZE,
            bridge_proof_max_range_len: defaults::zk::proof::BRIDGE_MAX_RANGE_LEN,
            bridge_proof_max_past_age_blocks: defaults::zk::proof::BRIDGE_MAX_PAST_AGE_BLOCKS,
            bridge_proof_max_future_drift_blocks:
                defaults::zk::proof::BRIDGE_MAX_FUTURE_DRIFT_BLOCKS,
            poseidon_params_id: defaults::confidential::POSEIDON_PARAMS_ID,
            pedersen_params_id: defaults::confidential::PEDERSEN_PARAMS_ID,
            kaigi_authorization_vk: None,

            kaigi_usage_vk: None,
            max_proof_size_bytes: defaults::confidential::MAX_PROOF_SIZE_BYTES,
            max_nullifiers_per_tx: defaults::confidential::MAX_NULLIFIERS_PER_TX,
            max_commitments_per_tx: defaults::confidential::MAX_COMMITMENTS_PER_TX,
            max_confidential_ops_per_block: defaults::confidential::MAX_CONFIDENTIAL_OPS_PER_BLOCK,
            verify_timeout: defaults::confidential::VERIFY_TIMEOUT,
            max_anchor_age_blocks: defaults::confidential::MAX_ANCHOR_AGE_BLOCKS,
            max_proof_bytes_block: defaults::confidential::MAX_PROOF_BYTES_BLOCK,
            max_verify_calls_per_tx: defaults::confidential::MAX_VERIFY_CALLS_PER_TX,
            max_verify_calls_per_block: defaults::confidential::MAX_VERIFY_CALLS_PER_BLOCK,
            max_public_inputs: defaults::confidential::MAX_PUBLIC_INPUTS,
            reorg_depth_bound: defaults::confidential::REORG_DEPTH_BOUND,
            policy_transition_delay_blocks: defaults::confidential::POLICY_TRANSITION_DELAY_BLOCKS,
            policy_transition_window_blocks:
                defaults::confidential::POLICY_TRANSITION_WINDOW_BLOCKS,
            policy_transition_max_per_height:
                defaults::confidential::POLICY_TRANSITION_MAX_PER_HEIGHT,
            tree_roots_history_len: nonzero!(4_usize),
            tree_frontier_checkpoint_interval:
                defaults::confidential::TREE_FRONTIER_CHECKPOINT_INTERVAL,
            registry_max_vk_entries: defaults::confidential::REGISTRY_MAX_VK_ENTRIES,
            registry_max_params_entries: defaults::confidential::REGISTRY_MAX_PARAMS_ENTRIES,
            registry_max_delta_per_block: defaults::confidential::REGISTRY_MAX_DELTA_PER_BLOCK,
            gas: cfg::ConfidentialGas {
                proof_base: defaults::confidential::gas::PROOF_BASE,
                per_public_input: defaults::confidential::gas::PER_PUBLIC_INPUT,
                per_proof_byte: defaults::confidential::gas::PER_PROOF_BYTE,
                per_nullifier: defaults::confidential::gas::PER_NULLIFIER,
                per_commitment: defaults::confidential::gas::PER_COMMITMENT,
            },
        })
        .expect("empty state accepts roots-cap test configuration");
    // Seed world: domain/account/asset and mint
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let domain_id: DomainId = DomainId::try_new("zkd", "universal").unwrap();
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("zkd", "universal").unwrap(),
            "zcoin".parse().unwrap(),
        );
    let owner = checked_random_zk_roots_account_id();
    for instr in [
        Register::domain(Domain::new(domain_id.clone())).into(),
        Register::account(NewAccount::new(owner.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset_def_id.clone(),
            "zcoin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            Some(domain_id.clone()),
        ))
        .into(),
        Mint::asset_quantity(10_000u64, AssetId::of(asset_def_id.clone(), owner.clone())).into(),
        // Register zk policy
        iroha_data_model::isi::zk::RegisterZkAsset::new(asset_def_id.clone(), None).into(),
    ] {
        stx.world
            .executor()
            .clone()
            .execute_instruction(&mut stx, &owner, instr)
            .unwrap();
    }
    // Seed authenticated-tree transitions directly; the syscall test only exercises root caps.
    let mut zk_state = stx
        .world
        .zk_assets()
        .get(&asset_def_id)
        .cloned()
        .expect("registered confidential asset state");
    for i in 0_u8..16 {
        let mut commitment = [7_u8; 32];
        commitment[0] = i.saturating_add(1);
        zk_state
            .push_commitment(commitment, nonzero!(4_usize))
            .expect("seed bounded confidential root history");
    }
    stx.world
        .zk_assets_mut_for_testing()
        .remove(asset_def_id.clone());
    stx.world
        .zk_assets_mut_for_testing()
        .insert(asset_def_id.clone(), zk_state);
    let zk_snapshot = stx
        .world
        .zk_assets()
        .iter()
        .map(|(asset_id, state)| (asset_id.clone(), state.clone()))
        .collect();
    stx.apply();
    // Build CoreHost and snapshot roots
    let mut vm = ivm::IVM::new(1_000_000);
    let mut host = CoreHost::new(owner.clone());
    host.set_zk_tree_roots_history_len(state.view().zk.tree_roots_history_len);
    host.set_zk_roots_snapshot(zk_snapshot)
        .expect("canonical confidential tree snapshot");
    let mut host = host;
    // Case 1: max=0 => bounded by cap
    let req = zk_verify::RootsGetRequest {
        asset_id: asset_def_id.to_string(),
        max: 0,
    };
    let payload = norito::to_bytes(&req).expect("encode");
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    vm.memory.preload_input(0, &tlv).expect("preload input");
    vm.set_register(10, Memory::INPUT_START);
    host.syscall(syscalls::SYSCALL_ZK_ROOTS_GET, &mut vm)
        .expect("syscall ok");
    let resp_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(resp_ptr).expect("valid tlv");
    let resp: zk_verify::RootsGetResponse =
        norito::decode_from_bytes(tlv.payload).expect("decode response");
    assert!(resp.roots.len() <= 4);
    assert_eq!(resp.roots.len(), 4);
    // Case 2: max=2 => bounded by 2
    let req = zk_verify::RootsGetRequest {
        asset_id: asset_def_id.to_string(),
        max: 2,
    };
    let payload = norito::to_bytes(&req).expect("encode");
    let tlv = make_tlv(PointerType::NoritoBytes as u16, &payload);
    vm.memory.preload_input(128, &tlv).expect("preload input");
    vm.set_register(10, Memory::INPUT_START + 128);
    host.syscall(syscalls::SYSCALL_ZK_ROOTS_GET, &mut vm)
        .expect("syscall ok");
    let resp_ptr = vm.register(10);
    let tlv = vm.memory.validate_tlv(resp_ptr).expect("valid tlv");
    let resp: zk_verify::RootsGetResponse =
        norito::decode_from_bytes(tlv.payload).expect("decode response");
    assert_eq!(resp.roots.len(), 2);
}
