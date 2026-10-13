//! Historical authenticated state cannot retire a current retry operation.

use super::*;
use iroha_data_model::sccp::light_client::{SccpLcInitExpectationV1, SccpLightClientParamsV1};
use iroha_sccp::{
    light_client::{
        initialize_light_client_with_profiles, profile::SccpChainProfilesV1,
        state::SccpLcMemoryStateV1,
    },
    test_support::ton::SyntheticTonChainV1,
    v1::{
        committee::committee_root,
        ton_cell::{Cell, CellBuilder, TonMinterInitV1, locked_code_refs, minter_initial_data},
    },
};
use iroha_sccp_wallet::{
    flow::{SccpFlowActionV1 as Action, SccpFlowV1, drive_step_with_rebroadcast},
    journal::{SccpFlowIdV1, SccpFlowKindV1, SccpJournalRoot, SccpStepOutcomeKindV1},
    pure::ton::{
        SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS, TonWalletKeyV1, WALLET_V5R1_MAINNET_ID,
        internal_message, recovery_row, retry_body, wallet_v5_transfer,
    },
};

const MINTER: [u8; 32] = [10; 32];
const TIME: u32 = 1_790_000_000;

fn minter_account(attempt: u64) -> Cell {
    let fixture: norito::json::Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sccp/ton_stateinit_v1.json"
    )))
    .unwrap();
    let keys: Vec<[u8; 48]> = fixture["vectors"][0]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| {
            hex::decode(key.as_str().unwrap().trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let locked = locked_code_refs();
    let data = minter_initial_data(&TonMinterInitV1 {
        taira_network_id: [1; 32],
        consensus_instance: [2; 32],
        route_revision: 3,
        max_supply: 1000,
        pin: SccpCommitteePinV1 {
            generation: 1,
            committee_root: committee_root(&keys).unwrap(),
            start_height: 5,
            until_ms: 10_000,
        },
        keys,
        wallet_code: locked[1],
        bucket_code: locked[2],
    })
    .unwrap();
    let tail = CellBuilder::new()
        .store_bit(true)
        .unwrap()
        .store_uint(0, 2)
        .unwrap()
        .store_uint(2, 2)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 8)
        .unwrap()
        .store_bytes(&[7; 32])
        .unwrap()
        .store_bytes(&[8; 32])
        .unwrap()
        .build();
    let row = CellBuilder::new()
        .store_uint(1, 3)
        .unwrap()
        .store_uint(2, 2)
        .unwrap()
        .store_uint(u128::from(attempt), 64)
        .unwrap()
        .store_uint(19, 64)
        .unwrap()
        .store_uint(10, 96)
        .unwrap()
        .store_uint(1, 10)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(11, 64)
        .unwrap()
        .store_uint(0, 2)
        .unwrap()
        .store_ref(tail)
        .unwrap()
        .build();
    let dictionary = CellBuilder::new()
        .store_uint(2, 2)
        .unwrap()
        .store_uint(64, 7)
        .unwrap()
        .store_uint(1, 64)
        .unwrap()
        .store_ref(row)
        .unwrap()
        .build();
    let book = CellBuilder::new()
        .store_uint(2, 64)
        .unwrap()
        .store_uint(1, 10)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_maybe_ref(Some(dictionary))
        .unwrap()
        .build();
    let state = CellBuilder::new()
        .store_bit(true)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_coins(0)
        .unwrap()
        .store_coins(0)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_ref(data.config)
        .unwrap()
        .store_ref(data.committee)
        .unwrap()
        .store_ref(data.checkpoints)
        .unwrap()
        .store_ref(book)
        .unwrap()
        .build();
    CellBuilder::new()
        .store_bit(true)
        .unwrap()
        .store_uint(2, 2)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 8)
        .unwrap()
        .store_bytes(&MINTER)
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(0, 3)
        .unwrap()
        .store_uint(0, 32)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_uint(0, 64)
        .unwrap()
        .store_coins(0)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_bit(true)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_bit(false)
        .unwrap()
        .store_maybe_ref(Some(locked[0]))
        .unwrap()
        .store_maybe_ref(Some(state))
        .unwrap()
        .store_bit(false)
        .unwrap()
        .build()
}

#[test]
fn genuine_older_minter_state_and_retired_wallet_preserve_original_pending_retry() {
    let chain = SyntheticTonChainV1::new([71; 32]);
    let profiles = SccpChainProfilesV1::genesis();
    let network = SccpNetworkV1::TonMainnet;
    let now = u64::from(TIME) * 1000 + 60_000;
    let mut lc = SccpLcMemoryStateV1::new();
    let initial = initialize_light_client_with_profiles(
        profiles,
        &lc,
        network,
        SccpLcInitExpectationV1::Absent,
        &SccpLightClientParamsV1::defaults_for(network).unwrap(),
        &chain.bootstrap(100, 0, TIME, TIME + 65536),
        now,
    )
    .unwrap();
    lc.install(network, &initial);
    let verified = |attempt, height| {
        let proof = chain.account_state_proof(
            MINTER,
            minter_account(attempt),
            height,
            height - 99,
            TIME + height - 100,
        );
        let state = verify_minter_state(&profiles.ton, &lc, &proof, MINTER, now).unwrap();
        let cut = authenticated_cut(&proof);
        (state, proof, cut)
    };
    let (baseline_state, baseline_proof, baseline_cut) = verified(2, 103);
    let original_row = baseline_state.recovery[0].row_boc.clone();
    let baseline_row =
        recovery_row(&iroha_sccp::v1::ton_cell::cell_from_boc(&original_row).unwrap()).unwrap();
    let (older_state, _, older_cut) = verified(1, 102);
    let (newer_state, _, newer_cut) = verified(3, 104);
    assert!(ton::test_wallet_retirement(8).retired());
    assert!(!recovery_changed(&older_state, 1, &baseline_row, &baseline_cut, &older_cut).unwrap());
    assert!(!recovery_changed(&older_state, 1, &baseline_row, &baseline_cut, &newer_cut).unwrap());
    assert!(recovery_changed(&newer_state, 1, &baseline_row, &baseline_cut, &newer_cut).unwrap());

    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
    std::fs::create_dir_all(&base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("older-minter-retry-")
        .tempdir_in(base)
        .unwrap();
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([7; 32])),
    );
    let id = SccpFlowIdV1 {
        kind: SccpFlowKindV1::TonRecovery,
        id: [4; 32],
    };
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network_id).unwrap().flow(&id).unwrap(),
        *network_id.as_bytes(),
    )
    .unwrap();
    let evidence = vec![
        flows::evidence("ton.original_minter.cut", &baseline_cut).unwrap(),
        flows::evidence("ton.original_minter.account_proof", &baseline_proof).unwrap(),
        SccpEvidenceItemV1 {
            label: "ton.recovery.original_row".into(),
            bytes: original_row,
        },
    ];
    assert_eq!(recovery_baseline(&evidence).unwrap(), baseline_cut);
    let key = TonWalletKeyV1::from_seed(&zeroize::Zeroizing::new([8; 32]));
    let body = retry_body(1, 1, &[9; 32]).unwrap();
    let message = internal_message(&MINTER, 100_000_000, true, body, None).unwrap();
    let signed = wallet_v5_transfer(
        &[9; 32],
        WALLET_V5R1_MAINNET_ID,
        7,
        TIME + 120,
        &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        &key,
    )
    .unwrap();
    let original_hash = iroha_sccp::ton_canonical_boc_single_root_hash_v1(&signed).unwrap();
    let step = flow
        .prepare(Action::RetryRecovery, network, signed, evidence)
        .unwrap();
    step.begin_submission().unwrap();
    let original = step.record().clone();
    let outcome = drive_step_with_rebroadcast::<eyre::Report>(
        &step,
        false,
        |_| {
            let changed =
                recovery_changed(&older_state, 1, &baseline_row, &baseline_cut, &older_cut)?;
            flows::retired_ton_outcome(
                changed.then(Vec::new),
                SccpStepOutcomeKindV1::Superseded,
                original_hash,
                || Ok(Some(ton::test_wallet_retirement(8))),
            )
        },
        |_| panic!("historical evidence cannot resend the original retry"),
    )
    .unwrap();
    assert!(outcome.is_none());
    drop(step);
    drop(flow);
    drop(root);
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network_id).unwrap().flow(&id).unwrap(),
        *network_id.as_bytes(),
    )
    .unwrap();
    let pending = flow.pending().unwrap().unwrap();
    assert_eq!(pending.record(), &original);
    assert!(pending.outcome().unwrap().is_none());
    assert!(pending.submission_recorded().unwrap());
    assert!(
        flow.prepare(Action::RetryRecovery, network, vec![1], vec![])
            .is_err()
    );
}

fn retry_fixture(attempt: u64, height: u32) -> (TonMinterStateV1, RecoveryCut, Evidence) {
    let chain = SyntheticTonChainV1::new([71; 32]);
    let profiles = SccpChainProfilesV1::genesis();
    let network = SccpNetworkV1::TonMainnet;
    let now = u64::from(TIME) * 1000 + 60_000;
    let mut lc = SccpLcMemoryStateV1::new();
    let initial = initialize_light_client_with_profiles(
        profiles,
        &lc,
        network,
        SccpLcInitExpectationV1::Absent,
        &SccpLightClientParamsV1::defaults_for(network).unwrap(),
        &chain.bootstrap(100, 0, TIME, TIME + 65536),
        now,
    )
    .unwrap();
    lc.install(network, &initial);
    let proof = chain.account_state_proof(
        MINTER,
        minter_account(attempt),
        height,
        height - 99,
        TIME + height - 100,
    );
    let state = verify_minter_state(&profiles.ton, &lc, &proof, MINTER, now).unwrap();
    let cut = authenticated_cut(&proof);
    let items = vec![
        flows::evidence("ton.original_minter.cut", &cut).unwrap(),
        flows::evidence("ton.original_minter.account_proof", &proof).unwrap(),
        SccpEvidenceItemV1 {
            label: "ton.recovery.original_row".into(),
            bytes: state.recovery[0].row_boc.clone(),
        },
    ];
    (state, cut, items)
}

#[test]
fn retry_reselection_uses_the_actual_locked_step_after_another_process_appends() {
    use crate::sccp::recovery::retry_baseline;
    use iroha_sccp_wallet::journal::SccpJournalOutcomeV1;
    let network = SccpNetworkV1::TonMainnet;
    let (_, _, evidence_a) = retry_fixture(2, 103);
    let (observed, observed_cut, observed_evidence) = retry_fixture(3, 104);
    let (_, _, evidence_b) = retry_fixture(4, 105);
    let base =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/sccp-continuation");
    std::fs::create_dir_all(&base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("reselected-retry-")
        .tempdir_in(base)
        .unwrap();
    let network_id = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed([7; 32])),
    );
    let id = SccpFlowIdV1 {
        kind: SccpFlowKindV1::TonRecovery,
        id: [5; 32],
    };
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network_id).unwrap().flow(&id).unwrap(),
        *network_id.as_bytes(),
    )
    .unwrap();
    let key = TonWalletKeyV1::from_seed(&zeroize::Zeroizing::new([8; 32]));
    let signed = |seqno| {
        let body = retry_body(1, 1, &[9; 32]).unwrap();
        let message = internal_message(&MINTER, 100_000_000, true, body, None).unwrap();
        wallet_v5_transfer(
            &[9; 32],
            WALLET_V5R1_MAINNET_ID,
            seqno,
            TIME + 120,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
            &key,
        )
        .unwrap()
    };
    let step_a = flow
        .prepare(Action::RetryRecovery, network, signed(7), evidence_a)
        .unwrap();
    step_a.begin_submission().unwrap();
    let (stale_row, stale_cut) = retry_baseline(&step_a).unwrap();
    let first_index = step_a.record().step;
    drop(step_a); // Process A's earlier selection no longer owns this step's lock.

    // Process B completes that original step, then prepares another real step at cut 105.
    let step_a = flow.latest(Action::RetryRecovery).unwrap().unwrap();
    step_a
        .complete(&SccpJournalOutcomeV1 {
            outcome: SccpStepOutcomeKindV1::Superseded,
            transaction: iroha_sccp::ton_canonical_boc_single_root_hash_v1(
                &step_a.record().submission,
            )
            .unwrap()
            .to_vec(),
            evidence: evidence_b.clone(),
        })
        .unwrap();
    drop(step_a);
    let step_b = flow
        .prepare(Action::RetryRecovery, network, signed(8), evidence_b)
        .unwrap();
    step_b.begin_submission().unwrap();
    let original_b = step_b.record().clone();
    assert_ne!(first_index, original_b.step);
    drop(step_b);

    // Process A's driver now selects B. Cut 104 would satisfy A's stale baseline, but cannot
    // finish the exact currently locked step whose original cut is already 105.
    assert!(recovery_changed(&observed, 1, &stale_row, &stale_cut, &observed_cut).unwrap());
    let selected = flow.latest(Action::RetryRecovery).unwrap().unwrap();
    assert_eq!(selected.record(), &original_b);
    let outcome = drive_step_with_rebroadcast::<eyre::Report>(
        &selected,
        false,
        |_| {
            let (row, cut) = retry_baseline(&selected)?;
            Ok(
                recovery_changed(&observed, 1, &row, &cut, &observed_cut)?.then(|| {
                    SccpJournalOutcomeV1 {
                        outcome: SccpStepOutcomeKindV1::Superseded,
                        transaction: iroha_sccp::ton_canonical_boc_single_root_hash_v1(
                            &selected.record().submission,
                        )
                        .unwrap()
                        .to_vec(),
                        evidence: observed_evidence.clone(),
                    }
                }),
            )
        },
        |_| panic!("step reselection cannot dispatch a replacement"),
    )
    .unwrap();
    assert!(outcome.is_none());
    drop(selected);
    drop(flow);
    drop(root);
    let root = SccpJournalRoot::open(&dir.path().join("journal")).unwrap();
    let flow = SccpFlowV1::open(
        root.network(&network_id).unwrap().flow(&id).unwrap(),
        *network_id.as_bytes(),
    )
    .unwrap();
    let pending = flow.pending().unwrap().unwrap();
    assert_eq!(pending.record(), &original_b);
    assert!(pending.outcome().unwrap().is_none());
    assert!(pending.submission_recorded().unwrap());
    assert!(
        flow.prepare(Action::RetryRecovery, network, signed(9), vec![])
            .is_err()
    );
}
