//! Original-source, rotation-boundary, bounded-path and typed-refusal controls.

use super::*;
use std::{num::NonZeroUsize, time::Duration};

use crate::{
    smartcontracts::isi::sccp::test_support::{authority, blank_state, header, sample_route},
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::{
    isi::sccp::InitializeSccpV1,
    parameter::{Parameter, SumeragiParameter, system::SumeragiNposParameters},
    sccp::{
        outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
        params::SccpParametersV1,
    },
};
use iroha_sccp::v1::{
    finality::verify_certificate,
    history::{history_root, verify_history_inclusion},
    merkle::{block_root, verify_block_inclusion},
    payload::SccpTransferPayloadV1,
};

fn control(stop: &AtomicBool) -> SccpNativeReadControl<'_> {
    SccpNativeReadControl {
        deadline: Instant::now() + Duration::from_secs(60),
        stop,
    }
}

/// Signed NPoS genesis initializes SCCP through its real instruction and output seal.
/// No test writes a generation, X, R or QC. The long epoch avoids an unrelated boundary
/// ceremony while a real heartbeat supplies the unchanged-key rotation test.
fn active_chain() -> CertifiedTestChain {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
    config.genesis_block_cadence_ms = NonZeroU64::new(1_000).unwrap();
    let npos = SumeragiNposParameters {
        epoch_length_blocks: NonZeroU64::new(3_600).unwrap(),
        max_validators: 4,
        ..SumeragiNposParameters::default()
    };
    config.genesis_parameters.extend([
        Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            npos.epoch_length_blocks,
        )),
        Parameter::Custom(npos.into_custom_parameter()),
    ]);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.staking.unbonding_delay = Duration::from_secs(21 * 86_400);
    nexus.staking.max_slash_bps = 1;
    config.nexus = Some(nexus);
    config.genesis_instructions.push(
        InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x5a; 32],
        }
        .into(),
    );
    CertifiedTestChain::start(config).expect("original signed SCCP genesis")
}

#[test]
fn genuine_certificate_retains_raw_result_signature_and_outgoing_rotation_generation() {
    let mut chain = active_chain();
    chain.commit_at(2_000, Vec::new());
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    {
        let view = chain.state().view();
        let answer = finality(
            &view,
            Some(NonZeroU64::new(2).unwrap()),
            &budget,
            control(&stop),
        )
        .unwrap();
        let original = read_commit_certificate(
            &view,
            NonZeroU64::new(2).unwrap(),
            &budget,
            control(&stop).deadline,
        )
        .unwrap();
        let raw = original.certificate();
        let qc: Qc = norito::decode_canonical(&raw.commit_qc).unwrap();
        let data = answer.data();
        assert_eq!(&data.header[..], &raw.result_preimage[..X_LEN]);
        assert_eq!(data.aggregate_signature, qc.agg_sig.0);
        let fixed = QcFixedV1::parse(&data.qc).unwrap();
        assert_eq!(
            fixed.result_body,
            body_digest(&raw.result_preimage[X_LEN..])
        );
        let verified = verify_certificate(
            &chain.instance().0,
            &data.qc,
            &data.header,
            &data.aggregate_signature,
            &data.committee,
        )
        .expect("independent native BLS check");
        assert_eq!(
            verified.result,
            result_of_preimage(&raw.result_preimage).unwrap().0
        );
        assert!(budget.reserved_bytes() > 0);
    }
    assert_eq!(budget.reserved_bytes(), 0);
    let started = store::committee_generations::get(chain.state().view().world(), &1)
        .unwrap()
        .start_timestamp_ms;
    let heartbeat = started + SccpParametersV1::taira_default().committee_heartbeat_ms;
    chain.commit_at(heartbeat, Vec::new());
    {
        let view = chain.state().view();
        let latest = finality(&view, None, &budget, control(&stop)).unwrap();
        let signing = SccpFinalityHeaderV1::parse(&latest.data().header).unwrap();
        let current = current_committee(&view, &budget, control(&stop)).unwrap();
        assert!(signing.is_rotation());
        assert_eq!(current.data().generation, signing.generation() + 1);
        assert_eq!(current.data().start_height, 4);
        assert_eq!(current.data().committee_root, signing.next_committee_root());
        assert_eq!(
            current.data().generation,
            *store::committee_current::get(view.world())
        );
        let selected = committee(
            &view,
            NonZeroU64::new(current.data().generation).unwrap(),
            &budget,
            control(&stop),
        )
        .unwrap();
        assert_eq!(selected.data(), current.data());
        let outgoing = committee(
            &view,
            NonZeroU64::new(signing.generation()).unwrap(),
            &budget,
            control(&stop),
        )
        .unwrap();
        assert_eq!(outgoing.data().end.as_ref().unwrap().end_height, 3);
        assert!(current.data().liable);
    }
    assert_eq!(budget.reserved_bytes(), 0);
    chain.commit_at(heartbeat + 1_000, Vec::new());
    let view = chain.state().view();
    let outgoing = finality(&view, NonZeroU64::new(3), &budget, control(&stop)).unwrap();
    let successor = finality(&view, NonZeroU64::new(4), &budget, control(&stop)).unwrap();
    let before = SccpFinalityHeaderV1::parse(&outgoing.data().header).unwrap();
    let after = SccpFinalityHeaderV1::parse(&successor.data().header).unwrap();
    assert!(before.is_rotation());
    assert_eq!(before.generation() + 1, after.generation());
    assert_eq!(before.next_committee_root(), after.committee_root());
    let rotations =
        committee_rotations(&view, before.generation(), 16, &budget, control(&stop)).unwrap();
    assert_eq!(rotations.data().len(), 1);
    assert_eq!(&rotations.data()[0].certificate, outgoing.data());
    assert_eq!(
        &rotations.data()[0].next_committee,
        &successor.data().committee
    );
    assert!(
        committee_rotations(&view, after.generation(), 16, &budget, control(&stop))
            .unwrap()
            .data()
            .is_empty()
    );
}

/// These private test overlays provide leaf inputs before the real output seal. They do not
/// supply finality, committee authority or public route governance. Both blocks below still
/// execute and retain their own original X, result and exact-quorum native certificate.
fn install_message(chain: &CertifiedTestChain, at_ms: u64, nonce: u64) -> [u8; 32] {
    let network = SccpNetworkV1::EthereumMainnet;
    let route = sample_route(network);
    let destination = route.revisions.get(&1).unwrap().destination_word;
    let payload = SccpTransferPayloadV1::outbound(
        network,
        nonce,
        1,
        at_ms + 86_400_000,
        1_000_000_000,
        vec![0x33; 32],
        vec![0x22; 20],
    )
    .unwrap();
    let id = payload.message_id(chain.network_id().as_bytes()).unwrap();
    let bytes = payload.encode().unwrap();
    chain.setup_world_at(at_ms, |stx| {
        store::routes::insert(stx, network, route).unwrap();
        store::block_leaves::insert(stx, (chain.height() + 1, 0), SccpLeafRefV1::transfer(id))
            .unwrap();
        store::outbound_messages::insert(
            stx,
            id,
            SccpOutboundMessageRecordV1 {
                network,
                revision: 1,
                nonce,
                height: chain.height() + 1,
                commitment_index: 0,
                deadline_ms: payload.deadline_ms,
                sender: authority(1),
                amount: payload.amount,
                payload: bytes,
                leaf: transfer_leaf(&id, &destination),
                status: SccpOutboundStatusV1::Recorded,
            },
        )
        .unwrap();
    });
    id
}

#[test]
fn message_direct_and_history_paths_bind_the_selected_original_header() {
    let mut chain = active_chain();
    let first = install_message(&chain, 2_000, 1);
    chain.commit_at(2_000, Vec::new());
    install_message(&chain, 3_000, 2);
    chain.commit_at(3_000, Vec::new());
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    let direct = message_proof(
        &view,
        first,
        SccpNativeProofAt::Record,
        &budget,
        control(&stop),
    )
    .unwrap();
    assert!(!direct.data().is_historical());
    assert!(direct.data().block.history_path.is_empty());
    assert_eq!(direct.data().block.history_index, 0);
    direct
        .data()
        .message_proof(chain.network_id().as_bytes(), &first)
        .unwrap();
    let historical = message_proof(
        &view,
        first,
        SccpNativeProofAt::Latest,
        &budget,
        control(&stop),
    )
    .unwrap();
    let data = historical.data();
    assert!(data.is_historical());
    let x = SccpFinalityHeaderV1::parse(&data.certificate.header).unwrap();
    let leaf = history_leaf(
        data.block.height,
        &data.block.sccp_root,
        data.block.message_count,
    );
    verify_history_inclusion(
        &leaf,
        data.block.history_index,
        x.history_size(),
        &data.block.history_path,
        &x.history_root(),
    )
    .unwrap();
    assert_eq!(data.block.height, direct.data().block.height);
    assert_eq!(data.block.sccp_root, direct.data().block.sccp_root);
    assert_eq!(data.block.message_count, direct.data().block.message_count);
    assert_eq!(data.payload, direct.data().payload);
    drop(historical);
    drop(direct);
    drop(view);
    let mut block = chain.state().block(header(4));
    let mut stx = block.transaction();
    let mut changed = store::outbound_messages::get(&*stx.world, &first)
        .unwrap()
        .clone();
    changed.height = 1;
    store::outbound_messages::insert(&mut stx, first, changed).unwrap();
    assert!(matches!(
        message_proof(
            &stx,
            first,
            SccpNativeProofAt::Record,
            &budget,
            control(&stop)
        ),
        Err(SccpNativeReadError::Invalid(
            "message record is outside committed certificate history"
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn streaming_history_and_block_paths_match_the_canonical_promote_odd_tree() {
    for size in (1..=128).chain([255, 256, 257, 511, 512, 513, 1023]) {
        let leaves = (0..size)
            .map(|n: usize| iroha_sccp::v1::hashes::keccak256(&[&n.to_be_bytes()]))
            .collect::<Vec<_>>();
        for index in [0, size / 2, size - 1] {
            let mut stream = StreamingPath::new(index as u64);
            for hash in &leaves {
                stream.push(*hash).unwrap();
            }
            let (root, path) = stream.finish().unwrap();
            assert_eq!(root, history_root(&leaves).unwrap());
            assert_eq!(
                iroha_sccp::v1::merkle::merkle_root(
                    &leaves[index],
                    index as u64,
                    size as u64,
                    &path
                )
                .unwrap(),
                root
            );
            if size <= MAX_BLOCK_LEAVES {
                let (block, path) = bounded_tree_path(&mut leaves.clone(), index as u64).unwrap();
                assert_eq!(block, block_root(&leaves).unwrap());
                verify_block_inclusion(&leaves[index], index as u32, size as u32, &path, &block)
                    .unwrap();
            }
        }
    }
    assert!(matches!(
        StreamingPath::new(0).finish(),
        Err(SccpNativeReadError::Invalid(_))
    ));
    assert!(matches!(
        bounded_tree_path(&mut [], 0),
        Err(SccpNativeReadError::Invalid(_))
    ));
}

#[test]
fn selectors_scope_cancellation_and_admission_are_separate_from_source_failures() {
    let mut chain = active_chain();
    chain.commit_at(2_000, Vec::new());
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    assert!(matches!(
        finality(&view, NonZeroU64::new(1), &budget, control(&stop)),
        Err(SccpNativeReadError::Request(_))
    ));
    assert!(matches!(
        finality(&view, NonZeroU64::new(3), &budget, control(&stop)),
        Err(SccpNativeReadError::Request(_))
    ));
    for (cursor, limit) in [(0, 1), (1, 0), (1, 17)] {
        assert!(matches!(
            committee_rotations(&view, cursor, limit, &budget, control(&stop)),
            Err(SccpNativeReadError::Request(_))
        ));
    }
    assert!(matches!(
        committee_rotations(&view, u64::MAX, 1, &budget, control(&stop)),
        Err(SccpNativeReadError::NotFound(_))
    ));
    assert!(matches!(
        finality(&view, None, &AllocationBudget::new(0), control(&stop)),
        Err(SccpNativeReadError::Allocation(_))
    ));
    stop.store(true, Ordering::Release);
    assert!(matches!(
        finality(&view, None, &budget, control(&stop)),
        Err(SccpNativeReadError::Cancelled)
    ));
    stop.store(false, Ordering::Release);
    assert!(matches!(
        finality(
            &view,
            None,
            &budget,
            SccpNativeReadControl {
                deadline: Instant::now(),
                stop: &stop
            }
        ),
        Err(SccpNativeReadError::Deadline)
    ));
    drop(view);
    assert!(with_state_view(chain.state(), control(&stop), |v| Ok(v.height())).unwrap() >= 2);
    chain
        .state()
        .with_held_view_publication_for_reader_test(|_| {
            assert!(matches!(
                with_state_view(chain.state(), control(&stop), |_| Ok(())),
                Err(SccpNativeReadError::View(StateViewError::Busy(_)))
            ));
        });
    stop.store(true, Ordering::Release);
    assert!(matches!(
        with_state_view(chain.state(), control(&stop), |_| -> Result<()> {
            panic!("cancelled callback must not run")
        }),
        Err(SccpNativeReadError::Cancelled)
    ));
    stop.store(false, Ordering::Release);
    assert!(matches!(
        source_identity(&blank_state().view(), control(&stop)),
        Err(SccpNativeReadError::Unavailable(_))
    ));
    crate::state::native_capture_fixture::with_native_capture_dataspace_source(
        |state, _, _, _, _| {
            assert!(matches!(
                finality(&state.view(), None, &budget, control(&stop)),
                Err(SccpNativeReadError::UnsupportedScope)
            ));
        },
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn inactive_original_and_corrupt_original_are_never_replaced_with_fabricated_certificates() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    assert!(matches!(
        finality(&chain.state().view(), None, &budget, control(&stop)),
        Err(SccpNativeReadError::Inactive)
    ));
    chain
        .kura()
        .corrupt_native_frame_for_test(NonZeroUsize::new(2).unwrap());
    assert!(matches!(
        finality(&chain.state().view(), None, &budget, control(&stop)),
        Err(SccpNativeReadError::Source(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn original_projection_rejects_bare_body_wrong_scope_identity_and_qc_substitution() {
    let mut chain = active_chain();
    chain.commit_at(2_000, Vec::new());
    let view = chain.state().view();
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let height = NonZeroU64::new(2).unwrap();
    let source = source_identity(&view, control(&stop)).unwrap();
    let owner = read_commit_certificate(&view, height, &budget, control(&stop).deadline).unwrap();
    let original = owner.certificate();
    assert!(
        project_original(
            view.world(),
            height,
            source,
            original,
            &budget,
            control(&stop)
        )
        .is_ok()
    );
    let mut bare = original.clone();
    bare.result_preimage.drain(..X_LEN);
    assert!(matches!(
        project_original(view.world(), height, source, &bare, &budget, control(&stop)),
        Err(SccpNativeReadError::CertifiedResult(_))
    ));
    let mut foreign = source;
    foreign.instance.0[0] ^= 1;
    assert!(matches!(
        project_original(
            view.world(),
            height,
            foreign,
            original,
            &budget,
            control(&stop)
        ),
        Err(SccpNativeReadError::Invalid(_))
    ));
    for mutation in 0..7 {
        let mut changed = original.clone();
        let mut qc: Qc = norito::decode_canonical(&changed.commit_qc).unwrap();
        match mutation {
            0 => qc.instance.0[0] ^= 1,
            1 => qc.kind = VoteKind::Prepare,
            2 => qc.height += 1,
            3 => qc.result.0[0] ^= 1,
            4 => qc.block_hash.0[0] ^= 1,
            5 => qc.epoch.context.0[0] ^= 1,
            // Four signers are a rejected superset of the exact three-vote quorum.
            6 => qc.signers = iroha_sumeragi::types::Bitmap::from_bytes(vec![0x0f]),
            _ => unreachable!(),
        }
        changed.commit_qc = norito::encode_canonical(&qc).unwrap();
        assert!(
            matches!(
                project_original(
                    view.world(),
                    height,
                    source,
                    &changed,
                    &budget,
                    control(&stop)
                ),
                Err(SccpNativeReadError::Invalid(_))
            ),
            "mutation {mutation}"
        );
    }
    let resource =
        norito::with_decode_limits_scope(norito::DecodeLimits::new(0, 0, 0, 0, 0), || {
            project_original(
                view.world(),
                height,
                source,
                original,
                &budget,
                control(&stop),
            )
        });
    assert!(
        matches!(resource, Err(SccpNativeReadError::DecodeResource(_))),
        "local inherited scope is preserved"
    );
}

#[test]
fn native_control_fields_and_paths_are_bound_to_the_original_committed_leaf() {
    use super::super::super::controls::{ControlCauseV1, record_control};
    let mut chain = active_chain();
    let network = SccpNetworkV1::EthereumMainnet;
    // Component fixture supplies the leaf producer's test-only cause, not a governance
    // authorization claim. The output seal and native BLS certificate remain original.
    chain.setup_world_at(2_000, |stx| {
        let mut route = sample_route(network);
        route.revisions.get_mut(&1).unwrap().destination_paused = true;
        store::routes::insert(stx, network, route).unwrap();
        assert_eq!(
            record_control(
                stx,
                network,
                1,
                ControlCauseV1::for_test([0x71; 32], [0x72; 32])
            )
            .unwrap(),
            1
        );
    });
    chain.commit_at(2_000, Vec::new());
    install_message(&chain, 3_000, 1);
    chain.commit_at(3_000, Vec::new());
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    let direct = control_proof(
        &view,
        network,
        1,
        1,
        SccpNativeProofAt::Record,
        &budget,
        control(&stop),
    )
    .unwrap();
    assert_eq!(direct.data().track, 1);
    assert!(direct.data().parliament_paused);
    assert_eq!(direct.data().fast_pause_until_ms, 0);
    assert_eq!(direct.data().certificate_id, [0x71; 32]);
    assert_eq!(direct.data().effect_hash, [0x72; 32]);
    assert!(!direct.data().is_historical());
    assert_eq!(direct.data().block.height, 2);
    direct.data().control_proof(network, 1).unwrap();
    let historical = control_proof(
        &view,
        network,
        1,
        1,
        SccpNativeProofAt::Latest,
        &budget,
        control(&stop),
    )
    .unwrap();
    let data = historical.data();
    assert!(data.is_historical());
    let x = SccpFinalityHeaderV1::parse(&data.certificate.header).unwrap();
    verify_history_inclusion(
        &history_leaf(
            data.block.height,
            &data.block.sccp_root,
            data.block.message_count,
        ),
        data.block.history_index,
        x.history_size(),
        &data.block.history_path,
        &x.history_root(),
    )
    .unwrap();
    assert_eq!(data.certificate_id, direct.data().certificate_id);
    assert_eq!(data.effect_hash, direct.data().effect_hash);
    drop(historical);
    drop(direct);
    drop(view);
    assert_eq!(budget.reserved_bytes(), 0);

    let mut block = chain.state().block(header(4));
    let mut stx = block.transaction();
    let mut changed = store::control_messages::get(&*stx.world, &(network, 1, 1))
        .unwrap()
        .clone();
    changed.effect_hash[0] ^= 1;
    store::control_messages::insert(&mut stx, (network, 1, 1), changed.clone()).unwrap();
    assert!(matches!(
        control_proof(
            &stx,
            network,
            1,
            1,
            SccpNativeProofAt::Record,
            &budget,
            control(&stop)
        ),
        Err(SccpNativeReadError::Invalid(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    changed.effect_hash[0] ^= 1;
    changed.height = 1;
    store::control_messages::insert(&mut stx, (network, 1, 1), changed).unwrap();
    assert!(matches!(
        control_proof(
            &stx,
            network,
            1,
            1,
            SccpNativeProofAt::Record,
            &budget,
            control(&stop)
        ),
        Err(SccpNativeReadError::Invalid(
            "control record is outside committed certificate history"
        ))
    ));
}

#[test]
fn generation_selection_uses_height_and_rejects_overlaps() {
    let chain = active_chain();
    let state = chain.state();
    let view = state.view();
    let mut first = store::committee_generations::get(view.world(), &1)
        .unwrap()
        .clone();
    let mut second = first.clone();
    drop(view);
    first.end = Some(super::super::super::generation::SccpGenerationEndV1 {
        end_height: 8,
        end_timestamp_ms: 8_000,
        next_committee_root: first.committee_root,
        successor_validity_ms: first.validity_ms,
    });
    second.generation = 2;
    second.start_height = 9;
    let mut block = state.block(header(2));
    let mut stx = block.transaction();
    store::committee_generations::insert(&mut stx, 1, first).unwrap();
    store::committee_generations::insert(&mut stx, 2, second.clone()).unwrap();
    let stop = AtomicBool::new(false);
    assert_eq!(
        signing_generation(&*stx.world, 8, control(&stop))
            .unwrap()
            .generation,
        1
    );
    assert_eq!(
        signing_generation(&*stx.world, 9, control(&stop))
            .unwrap()
            .generation,
        2
    );
    let budget = AllocationBudget::new(128 << 20);
    assert!(matches!(
        committee_rotations(&stx, 1, 1, &budget, control(&stop)),
        Err(SccpNativeReadError::Invalid(
            "recorded rotation end is outside committed certificate history"
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    second.start_height = 8;
    store::committee_generations::insert(&mut stx, 2, second).unwrap();
    assert!(matches!(
        signing_generation(&*stx.world, 8, control(&stop)),
        Err(SccpNativeReadError::Unavailable(_))
    ));
}

#[test]
fn committee_projection_retains_every_field_and_original_nested_allocation_charge() {
    use crate::smartcontracts::isi::sccp::{
        generation::SccpGenerationMemberV1 as StoredMember, test_support::sample_generation,
    };
    use iroha_data_model::account::{AccountId, MultisigMember, MultisigPolicy};
    let stop = AtomicBool::new(false);
    let mut record = sample_generation(2, 8);
    let keys = [0x61, 0x62].map(|seed| {
        iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
    });
    let multisig = AccountId::new_multisig(
        MultisigPolicy::new(
            2,
            keys.iter()
                .map(|key| MultisigMember::new(key.public_key().clone(), 1).unwrap())
                .collect(),
        )
        .unwrap(),
    );
    record.members[0] = Some(StoredMember {
        lane_id: iroha_model_base::topology::LaneId::new(u32::MAX),
        validator: multisig,
        activation_height: 7,
    });
    record.members[2] = Some(StoredMember {
        lane_id: iroha_model_base::topology::LaneId::new(0),
        validator: authority(0x63),
        activation_height: 8,
    });
    record.end = Some(super::super::super::generation::SccpGenerationEndV1 {
        end_height: 9,
        end_timestamp_ms: record.start_timestamp_ms + 4_000,
        next_committee_root: [0x71; 32],
        successor_validity_ms: record.validity_ms,
    });
    record.dest_cleared_lc = Some(record.liable_until_lc);
    assert!(record.is_well_formed());
    let demand = generation_allocation_bytes(&record, control(&stop)).unwrap();
    let inline = size_of::<SccpGenerationV1>()
        + record.keys.len() * 48
        + record.members.len() * size_of::<Option<SccpGenerationMemberV1>>();
    let mut nested = 0;
    for member in record.members.iter().flatten() {
        member
            .validator
            .for_each_admission_clone_layout(|layout| nested += layout.size())
            .unwrap();
    }
    assert!(
        nested > 2 * 33,
        "multisig member vector and all key owners are included"
    );
    assert_eq!(demand, inline + nested);
    let too_small = AllocationBudget::new(demand - 1);
    assert!(matches!(
        project_generation(&record, 3, 0, &too_small, control(&stop)),
        Err(SccpNativeReadError::Allocation(_))
    ));
    assert_eq!(too_small.reserved_bytes(), 0);
    let budget = AllocationBudget::new(demand);
    for cause in [
        StoredGenerationCause::Genesis,
        StoredGenerationCause::KeyChange,
        StoredGenerationCause::Heartbeat,
        StoredGenerationCause::Resync,
    ] {
        record.cause = cause;
        let answer =
            project_generation(&record, 3, record.start_lc, &budget, control(&stop)).unwrap();
        let data = answer.data();
        assert_eq!(budget.reserved_bytes(), demand);
        assert_eq!(data.generation, record.generation);
        assert_eq!(data.committee_root, record.committee_root);
        assert_eq!(
            data.cause,
            match cause {
                StoredGenerationCause::Genesis => SccpGenerationCauseV1::Genesis,
                StoredGenerationCause::KeyChange => SccpGenerationCauseV1::KeyChange,
                StoredGenerationCause::Heartbeat => SccpGenerationCauseV1::Heartbeat,
                StoredGenerationCause::Resync => SccpGenerationCauseV1::Resync,
            }
        );
        assert_eq!(data.keys, record.keys);
        assert_eq!(data.members.len(), record.members.len());
        for (actual, expected) in data.members.iter().zip(&record.members) {
            match (actual, expected) {
                (None, None) => (),
                (Some(actual), Some(expected)) => {
                    assert_eq!(actual.lane_id, expected.lane_id.as_u32());
                    assert_eq!(actual.validator, expected.validator);
                    assert_eq!(actual.activation_height, expected.activation_height);
                }
                _ => panic!("absent registration must remain absent"),
            }
        }
        assert_eq!(
            (data.start_height, data.start_timestamp_ms, data.start_lc),
            (
                record.start_height,
                record.start_timestamp_ms,
                record.start_lc
            )
        );
        assert_eq!(
            (
                data.validity_ms,
                data.deadline_ms,
                data.grace_ms,
                data.progress_cap_ms
            ),
            (
                record.validity_ms,
                record.deadline_ms,
                record.grace_ms,
                record.progress_cap_ms
            )
        );
        assert_eq!(
            (data.liable_until_lc, data.dest_cleared_lc),
            (record.liable_until_lc, record.dest_cleared_lc)
        );
        let end = data.end.as_ref().unwrap();
        let source_end = record.end.unwrap();
        assert_eq!(
            (
                end.end_height,
                end.end_timestamp_ms,
                end.next_committee_root,
                end.successor_validity_ms
            ),
            (
                source_end.end_height,
                source_end.end_timestamp_ms,
                source_end.next_committee_root,
                source_end.successor_validity_ms
            )
        );
        assert!(data.liable);
        drop(answer);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    for cleared in [None, Some(record.liable_until_lc)] {
        record.dest_cleared_lc = cleared;
        let last = cleared.map_or(record.liable_until_lc + record.progress_cap_ms, |lc| {
            lc + record.grace_ms
        });
        for (clock, expected) in [(last, true), (last + 1, false)] {
            let answer = project_generation(&record, 3, clock, &budget, control(&stop)).unwrap();
            assert_eq!(
                answer.data().liable,
                expected,
                "inclusive liability boundary"
            );
        }
        let answer = project_generation(
            &record,
            record.generation,
            u64::MAX,
            &budget,
            control(&stop),
        )
        .unwrap();
        assert!(
            answer.data().liable,
            "actual current generation remains liable"
        );
    }
    assert_eq!(budget.reserved_bytes(), 0);
    record.members.pop();
    assert!(matches!(
        project_generation(&record, 3, 0, &budget, control(&stop)),
        Err(SccpNativeReadError::Unavailable(_))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn committee_reads_distinguish_absence_authority_local_refusal_and_current_source_loss() {
    let chain = active_chain();
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    let first = current_committee(&view, &budget, control(&stop)).unwrap();
    assert_eq!(
        first.data().generation,
        1,
        "genesis generation DATA is available without a Commit certificate"
    );
    drop(first);
    assert!(matches!(
        committee(
            &view,
            NonZeroU64::new(u64::MAX).unwrap(),
            &budget,
            control(&stop)
        ),
        Err(SccpNativeReadError::NotFound(_))
    ));
    assert!(matches!(
        current_committee(&view, &AllocationBudget::new(0), control(&stop)),
        Err(SccpNativeReadError::Allocation(_))
    ));
    stop.store(true, Ordering::Release);
    assert!(matches!(
        current_committee(&view, &budget, control(&stop)),
        Err(SccpNativeReadError::Cancelled)
    ));
    stop.store(false, Ordering::Release);
    assert!(matches!(
        committee(
            &view,
            NonZeroU64::new(1).unwrap(),
            &budget,
            SccpNativeReadControl {
                deadline: Instant::now(),
                stop: &stop
            }
        ),
        Err(SccpNativeReadError::Deadline)
    ));
    drop(view);
    assert!(matches!(
        current_committee(&blank_state().view(), &budget, control(&stop)),
        Err(SccpNativeReadError::Unavailable(_))
    ));
    crate::state::native_capture_fixture::with_native_capture_dataspace_source(
        |state, _, _, _, _| {
            assert!(matches!(
                current_committee(&state.view(), &budget, control(&stop)),
                Err(SccpNativeReadError::UnsupportedScope)
            ));
            assert!(matches!(
                committee(
                    &state.view(),
                    NonZeroU64::new(1).unwrap(),
                    &budget,
                    control(&stop)
                ),
                Err(SccpNativeReadError::UnsupportedScope)
            ));
        },
    );
    let mut block = chain.state().block(header(2));
    let mut stx = block.transaction();
    store::committee_current::set(&mut stx, 99);
    assert!(matches!(
        current_committee(&stx, &budget, control(&stop)),
        Err(SccpNativeReadError::Unavailable(_))
    ));
    assert!(
        matches!(
            committee(&stx, NonZeroU64::new(100).unwrap(), &budget, control(&stop)),
            Err(SccpNativeReadError::Unavailable(_))
        ),
        "missing current source cannot be disguised as requested absence"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}
