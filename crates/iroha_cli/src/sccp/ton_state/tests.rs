//! Original effect predicates remain separate from fee-wallet nonce retirement.

use super::*;
use iroha_sccp::{
    light_client::ton::wallet_state::TonRecoveryStateV1, v1::committee::CommitteeStateV1,
};

fn state() -> TonMinterStateV1 {
    TonMinterStateV1 {
        initialized: true,
        network: [1; 32],
        instance: [2; 32],
        revision: 3,
        initial: SccpCommitteePinV1 {
            generation: 1,
            committee_root: [4; 32],
            start_height: 5,
            until_ms: 10_000,
        },
        committee: CommitteeStateV1 {
            root: [4; 32],
            generation: 1,
            start: 5,
            high: 4,
            until_ms: 10_000,
            equivocated: false,
        },
        checkpoints: vec![],
        total_supply: 0,
        pending_supply: 0,
        max_supply: 1000,
        outbound_nonce: 0,
        op_count: 0,
        control_nonce: 3,
        parliament_paused: false,
        fast_pause_until_ms: 0,
        deployed_buckets: 0,
        activated_buckets: 0,
        next_operation_id: 2,
        recovery: vec![TonRecoveryStateV1 {
            operation_id: 1,
            identity: [5; 32],
            stage: 2,
            phase: 2,
            attempt: 1,
            row_boc: vec![],
        }],
    }
}

#[test]
fn identity_and_progress_require_exact_native_scope_and_requested_coordinates() {
    let mut state = state();
    assert!(identity(&state, [1; 32], [2; 32], 3).is_ok());
    assert!(identity(&state, [0; 32], [2; 32], 3).is_err());
    assert!(identity(&state, [1; 32], [0; 32], 3).is_err());
    assert!(identity(&state, [1; 32], [2; 32], 4).is_err());
    assert!(progress_ready(&state, Some(3), Some(1)));
    assert!(!progress_ready(&state, Some(4), Some(1)));
    assert!(!progress_ready(&state, Some(3), Some(2)));
    assert!(!progress_ready(&state, None, None));
    state.initialized = false;
    assert!(!progress_ready(&state, Some(3), Some(1)));
}

#[test]
fn deployment_requires_exact_initial_pin_cap_and_completed_initialization() {
    let mut state = state();
    let mut pin = state.initial;
    assert!(deployment_ready(&state, &pin, 1000).unwrap());
    assert!(deployment_ready(&state, &pin, 1001).is_err());
    pin.until_ms += 1;
    assert!(deployment_ready(&state, &pin, 1000).is_err());
    state.initialized = false;
    assert!(!deployment_ready(&state, &state.initial, 1000).unwrap());
}

#[test]
fn recovery_absence_needs_original_admission_and_changes_preserve_cause() {
    let mut state = state();
    state.recovery[0].stage = 4;
    let baseline = cut(100, 10);
    let observed = cut(101, 11);
    let initial = RecoveryRowV1 {
        identity: [5; 32],
        stage: 4,
        phase: 2,
        attempt: 1,
    };
    assert!(!recovery_changed(&state, 1, &initial, &baseline, &observed).unwrap());
    state.recovery[0].attempt = 2;
    assert!(recovery_changed(&state, 1, &initial, &baseline, &observed).unwrap());
    assert!(!recovery_changed(&state, 1, &initial, &observed, &baseline).unwrap());
    assert!(!recovery_changed(&state, 1, &initial, &observed, &observed).unwrap());
    let mut unchanged_shard = observed;
    unchanged_shard.shard = baseline.shard;
    assert!(!recovery_changed(&state, 1, &initial, &baseline, &unchanged_shard).unwrap());
    state.recovery[0].identity[0] ^= 1;
    assert!(recovery_changed(&state, 1, &initial, &baseline, &observed).is_err());
    state.recovery.clear();
    assert!(recovery_changed(&state, 1, &initial, &baseline, &observed).unwrap());
    assert!(!recovery_changed(&state, 1, &initial, &observed, &baseline).unwrap());
    assert!(!recovery_changed(&state, 2, &initial, &baseline, &observed).unwrap());
    assert!(!recovery_changed(&state, 0, &initial, &baseline, &observed).unwrap());
    state.initialized = false;
    assert!(!recovery_changed(&state, 1, &initial, &baseline, &observed).unwrap());
}

fn cut(masterchain_seqno: u32, shard_seqno: u32) -> RecoveryCut {
    let block = |workchain, seqno| TonBlockIdExtV1 {
        workchain,
        shard: 0x8000_0000_0000_0000,
        seqno,
        root_hash: [7; 32],
        file_hash: [8; 32],
    };
    RecoveryCut {
        masterchain: block(-1, masterchain_seqno),
        shard: block(0, shard_seqno),
    }
}

#[test]
fn recovery_transitions_follow_the_locked_contract_instead_of_any_coordinate_change() {
    let row = |stage, phase, attempt| RecoveryRowV1 {
        identity: [5; 32],
        stage,
        phase,
        attempt,
    };
    assert!(!forward_recovery(&row(4, 2, 2), 4, 2, 1));
    assert!(!forward_recovery(&row(4, 2, 2), 4, 0, 2));
    assert!(!forward_recovery(&row(4, 1, 2), 4, 0, 3));
    assert!(!forward_recovery(&row(4, 0, 2), 4, 3, 2));
    assert!(!forward_recovery(&row(2, 0, 1), 2, 0, 2));
    assert!(!forward_recovery(&row(3, 1, 1), 4, 2, 0));
    assert!(!forward_recovery(&row(4, 2, 1), 3, 0, 1));
    assert!(!forward_recovery(&row(1, 0, 1), 2, 0, 1));
    assert!(forward_recovery(&row(4, 2, 0), 4, 0, 1));
    assert!(forward_recovery(&row(1, 2, 1), 1, 1, 3));
    assert!(forward_recovery(&row(1, 3, 1), 1, 2, 1));
    assert!(forward_recovery(&row(2, 3, 1), 2, 1, 1));
    assert!(forward_recovery(&row(2, 0, 1), 3, 0, 1));
    assert!(forward_recovery(&row(2, 1, 1), 4, 2, 0));
    assert!(forward_recovery(&row(3, 0, 1), 4, 2, 0));
}

#[test]
fn baseline_cut_requires_unique_retained_proof_and_uses_backlink_target() {
    use iroha_sccp::light_client::ton::TonBackLinkV1;
    let chain = iroha_sccp::test_support::ton::SyntheticTonChainV1::new([73; 32]);
    let mut proof = chain.wallet_state_proof([9; 32], 0x7fff_ff11, 3, [5; 32], 1_790_000_000);
    let TonMasterchainAnchorV1::Signed(fresh) = proof.masterchain.clone() else {
        unreachable!()
    };
    let mut target = fresh.block_id;
    target.seqno -= 1;
    proof.masterchain = TonMasterchainAnchorV1::BackLink(TonBackLinkV1 {
        fresh,
        state_proof: vec![],
        block_id: target,
        header_proof: vec![],
    });
    // This tests custody metadata extraction, not authentication of this synthetic back link.
    let baseline = authenticated_cut(&proof);
    assert_eq!(baseline.masterchain, target);
    let items = vec![
        flows::evidence("ton.original_minter.cut", &baseline).unwrap(),
        flows::evidence("ton.original_minter.account_proof", &proof).unwrap(),
    ];
    assert_eq!(recovery_baseline(&items).unwrap(), baseline);
    assert!(recovery_baseline(&items[1..]).is_err());
    assert!(recovery_baseline(&items[..1]).is_err());
    let mut repeated = items.clone();
    repeated.push(items[0].clone());
    assert!(recovery_baseline(&repeated).is_err());
    let mut detached = items;
    detached[0] = flows::evidence("ton.original_minter.cut", &cut(999, 999)).unwrap();
    assert!(recovery_baseline(&detached).is_err());
}
