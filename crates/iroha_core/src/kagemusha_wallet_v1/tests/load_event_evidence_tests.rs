//! Retained ordinary Load evidence through native finality, growth and exact replay.

use super::*;
use crate::sumeragi::{
    finality::NativeFinalityCursorV1,
    test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_allocation::AllocationBudget;
use std::{
    num::{NonZeroU16, NonZeroU64},
    time::{Duration, Instant},
};

pub(super) fn check_retained_load_event(
    chain: &CertifiedTestChain,
    memory: &Memory,
    original: &KagemushaWalletLoadReceiptV1,
) {
    let budget = AllocationBudget::new(2 * 1024 * 1024 * 1024);
    let mut cursor = NativeFinalityCursorV1::new();
    let deadline = || Instant::now() + Duration::from_secs(60);
    let maximum = NonZeroU16::new(64).unwrap();
    let native = cursor
        .advance_to_height(
            &chain.state().view(),
            NonZeroU64::new(original.block_height).unwrap(),
            &budget,
            deadline(),
            maximum,
        )
        .unwrap()
        .unwrap();
    {
        let view = chain.state().view();
        let limits = norito::DecodeLimits::new(2_000_000, 2_000_000, 16_000_000, 32_000_000, 128);
        let source = CommittedLoadReceipts::new(&view, 2_000_000, limits).unwrap();
        let evidence = source
            .event_evidence_for(
                &native,
                &memory.authority,
                &original.scheme_id,
                &original.wallet_id,
                &original.request_id,
            )
            .unwrap();
        assert_eq!(evidence.verified().receipt(), original);
        let raw = source
            .event_path_for(
                &memory.authority,
                &original.scheme_id,
                &original.wallet_id,
                &original.request_id,
            )
            .unwrap();
        assert_eq!(&raw, evidence.path());
        assert!(
            source
                .event_path_for(
                    &memory.registration.reserve,
                    &original.scheme_id,
                    &original.wallet_id,
                    &original.request_id
                )
                .is_err()
        );
        assert!(
            source
                .event_path_for(
                    &memory.authority,
                    &original.scheme_id,
                    &original.wallet_id,
                    &[0xff; 32]
                )
                .is_err()
        );

        assert_eq!(evidence.path().height(), original.block_height);
        assert_eq!(
            evidence.path().receipt_digest(),
            &original.receipt_digest().unwrap()
        );
        assert_eq!(
            Some(evidence.path().commitment()),
            native.block().execution().event_commitment
        );
        assert!(
            source
                .event_evidence_for(
                    &native,
                    &memory.registration.reserve,
                    &original.scheme_id,
                    &original.wallet_id,
                    &original.request_id,
                )
                .is_err()
        );
        let mut missing = view
            .world()
            .kagemusha_wallet_ledger()
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<BTreeMap<_, _>>();
        missing.remove(&event_evidence::key(original.receipt_digest().unwrap()));
        assert!(
            storage::validate_snapshot(missing.iter(), |key| missing.get(key).map(Vec::as_slice))
                .is_err()
        );
    }
    drop(native);
    let wrong = cursor
        .advance_to_height(
            &chain.state().view(),
            NonZeroU64::new(original.block_height + 1).unwrap(),
            &budget,
            deadline(),
            maximum,
        )
        .unwrap()
        .unwrap();
    {
        let view = chain.state().view();
        let source = CommittedLoadReceipts::new(
            &view,
            2_000_000,
            norito::canonical_decode_limits(2_000_000),
        )
        .unwrap();
        assert!(matches!(
            source.event_evidence_for(
                &wrong,
                &memory.authority,
                &original.scheme_id,
                &original.wallet_id,
                &original.request_id,
            ),
            Err(Error::Binding)
        ));
    }
    drop(wrong);
    drop(cursor);
    assert_eq!(budget.reserved_bytes(), 0);

    // Both nodes have the same explicit enrollment fixture; all subsequent Load
    // execution, retention, witness, R, QC and replay use the ordinary owners.
    let world = world_state(memory, true).world;
    let mut replay = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
    assert_eq!(replay.network_id(), chain.network_id());
    replay.setup_world_at(2_000, |tx| {
        tx.current_network_entrypoint_hash = Some(HashOf::from_untyped_unchecked(Hash::new(
            b"registration fixture",
        )));
        wsv::WsvLedger::new(tx, &memory.registration.reserve)
            .unwrap()
            .register(memory.registration.clone())
            .unwrap();
        tx.world.kagemusha_wallet_ledger.insert(
            storage::key(storage::WALLET, original.scheme_id, original.wallet_id),
            storage::encode(&WalletRecord {
                asset: memory.registration.asset.asset_digest(),
                phase: Phase::Active,
                activation: [0x93; 32],
                next_load: 0,
            })
            .unwrap(),
        );
    });
    replay.replay_from(chain).unwrap();
    let expected = chain
        .state()
        .view()
        .world()
        .kagemusha_wallet_ledger()
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect::<BTreeMap<_, _>>();
    let actual = replay
        .state()
        .view()
        .world()
        .kagemusha_wallet_ledger()
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual, expected,
        "replay retains the exact original event paths"
    );
    for height in 2..=chain.height() {
        assert_eq!(
            replay.committed(height).commitment(),
            chain.committed(height).commitment()
        );
    }
}
