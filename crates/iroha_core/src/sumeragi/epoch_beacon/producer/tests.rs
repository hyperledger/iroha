//! Native producer coverage over an actually executed/certified four-validator prefix.
//!
//! The DKG/session is explicit component prestate. Pulse demand is consensus-native: the
//! fixture chain is NPoS with a ten-block epoch, so its ninth height is the pre-boundary height
//! (`height + 1 == authorization.last_height`) and no governance row takes part in creating it.
//! The prefix's genesis, native parent hash and R are real; this fixture does not claim
//! live-network qualification of the seeded component rows. The Permissioned [`prefix`] has no
//! native pulse cadence and is the no-demand source.

use super::*;
use crate::{
    beacon::{
        GlobalThresholdBeaconCapabilityErrorV1, GlobalThresholdBeaconPartialSigningCapabilityV1,
        InMemoryGlobalThresholdBeaconPartialSignerV1,
        RetainedFinalizedGlobalThresholdBeaconSessionV1, ValidatedGlobalThresholdBeaconSessionV1,
        prepared_session_and_signers_fixture_for_keys_v1,
    },
    state::{GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalancePolicy, AssetDefinition},
    block::consensus::SumeragiRootScope,
    consensus::{
        GLOBAL_THRESHOLD_BEACON_VERSION_V1, GlobalThresholdBeaconDkgSessionV1,
        GlobalThresholdBeaconPartialSignatureV1,
    },
    governance::types::BeaconSessionId,
    isi::Register,
    nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters, SumeragiParameter},
    },
};
use iroha_model_base::{metadata::Metadata, topology::LaneId};
use iroha_primitives::numeric::{NumericSpec, Quantity};
use std::{
    collections::BTreeSet,
    io::Write as _,
    num::NonZeroU64,
    sync::atomic::{AtomicUsize, Ordering},
};

struct CountedSigner {
    inner: InMemoryGlobalThresholdBeaconPartialSignerV1,
    count: Arc<AtomicUsize>,
}
impl GlobalThresholdBeaconPartialSignerV1 for CountedSigner {
    fn attest_partial_signing_capability(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalThresholdBeaconCapabilityErrorV1,
    > {
        self.inner
            .attest_partial_signing_capability(session, expected_signer_index)
    }
    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<GlobalThresholdBeaconPartialSignatureV1, String> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.inner.sign_partial(session, payload)
    }
}

struct Fixture {
    chain: CertifiedTestChain,
    keys: Vec<PublicKey>,
    producers: Vec<NativeBeaconProducer>,
    counts: Vec<Arc<AtomicUsize>>,
    context: ApplicationControlContext,
}
/// Length of the fixture's NPoS epoch: heights 1..=10, so the native pulse height is 9.
const NPOS_EPOCH_LENGTH_BLOCKS: u64 = 10;

/// A Permissioned prefix through height 8. It has no native pulse cadence: no height of this
/// chain demands a pulse.
fn prefix() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    while chain.height() < 8 {
        chain.commit(Vec::new());
    }
    chain
}
/// An actually executed NPoS prefix through `height` whose signed genesis fixes a ten-block
/// epoch. Only its pre-boundary height 9 demands a pulse; every other height is ordinary.
fn npos_prefix(height: u64) -> CertifiedTestChain {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    let policy = SumeragiNposParameters {
        epoch_length_blocks: NonZeroU64::new(NPOS_EPOCH_LENGTH_BLOCKS).unwrap(),
        epoch_seed: [0x62; 32],
        evidence_horizon_blocks: 1,
        slashing_delay_blocks: 1,
        ..SumeragiNposParameters::default()
    };
    policy.validate().expect("bounded ten-block fixture policy");
    // The signed genesis carries the network currency its boundary reconciles.
    config.genesis_instructions.push(
        Register::asset_definition(AssetDefinition::new(
            policy.xor_asset_definition_id.clone(),
            "Network XOR",
            NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    );
    config.genesis_parameters.extend([
        Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            policy.epoch_length_blocks,
        )),
        Parameter::Custom(policy.into_custom_parameter()),
    ]);
    let mut chain = CertifiedTestChain::start(config).expect("actual signed NPoS genesis");
    while chain.height() < height {
        chain.commit(Vec::new());
    }
    chain
}
fn context(chain: &CertifiedTestChain) -> ApplicationControlContext {
    let parent = chain.committed(chain.height());
    let view = chain.state().view();
    let scheduled = view
        .world()
        .consensus_schedule()
        .ready(chain.height() + 1)
        .unwrap();
    ApplicationControlContext {
        instance: chain.instance(),
        epoch: schedule::core_epoch(&scheduled.epoch).unwrap().id,
        height: chain.height() + 1,
        parent_hash: parent.core_hash(),
        parent_result: parent.result(),
    }
}
fn build_context(context: &ApplicationControlContext, view: u64) -> ControlWitnessContext {
    ControlWitnessContext {
        height: context.height,
        view,
        epoch: context.epoch,
        parent_hash: context.parent_hash,
        parent_result: context.parent_result,
    }
}
/// The generic native-beacon fixture: consensus-native NPoS demand at the pre-boundary height 9.
fn fixture() -> Fixture {
    let fixture = seeded(npos_prefix(8));
    {
        let view = fixture.chain.state().view();
        let retained = view.world().consensus_schedule();
        let current = &retained.ready(9).unwrap().epoch;
        assert_eq!(current.mode, ConsensusMode::Npos);
        assert_eq!(current.authorization.last_height, NPOS_EPOCH_LENGTH_BLOCKS);
        assert_eq!(
            current.authorization.beacon,
            BeaconEpochBindingV1::Bootstrap,
            "the genesis epoch admits the seeded session under its bootstrap binding"
        );
        assert!(
            view.world()
                .parliament_required_beacon_pulse_slots()
                .iter()
                .next()
                .is_none(),
            "no governance row takes part in the fixture's demand"
        );
        assert!(
            super::super::required(SumeragiRootScope::Global, view.world(), current, 9).unwrap(),
            "the pre-boundary height is the consensus-native demand"
        );
        assert!(
            !super::super::required(SumeragiRootScope::Global, view.world(), current, 8).unwrap()
                && !super::super::required(SumeragiRootScope::Global, view.world(), current, 10)
                    .unwrap(),
            "ordinary and boundary heights demand no pulse"
        );
    }
    fixture
}

/// Seed the genuinely proved DKG session as active component prestate over an executed
/// eight-block prefix and attach one producer per validator seat. Demand is whatever the
/// chain itself authenticates at height 9; this function creates none.
fn seeded(chain: CertifiedTestChain) -> Fixture {
    assert_eq!(chain.height(), 8);
    let mut pairs = (0xC1..=0xC4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    let roster = pairs
        .iter()
        .map(|pair| iroha_model_base::peer::PeerId::new(pair.public_key().clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        roster,
        chain
            .validators()
            .iter()
            .map(|(peer, _)| peer.clone())
            .collect::<Vec<_>>()
    );
    let current = chain
        .state()
        .view()
        .world()
        .consensus_schedule()
        .ready(9)
        .unwrap()
        .epoch
        .clone();
    let id: [u8; 32] = Hash::new(b"native producer exact fixture DKG").into();
    let dkg = GlobalThresholdBeaconDkgSessionV1 {
        version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        network_id: chain.network_id(),
        session_id: id,
        attempt_id: id,
        authority_generation: current.authorization.authority_generation,
        roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
        committee_size: 4,
        threshold: 2,
        start_height: 1,
        commitments_end_height: 2,
        deliveries_end_height: 3,
        acceptances_end_height: 4,
    };
    let (session, signers) = prepared_session_and_signers_fixture_for_keys_v1(
        dkg,
        &pairs,
        &chain.state().ivm_execution_budget(),
    );
    let mut record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        session: session.clone(),
        activated_at_height: None,
        retired_at_height: None,
    };
    record
        .activate(session.record().adaptive_dkg.finalized_at_height)
        .unwrap();
    assert!(session.record().adaptive_dkg.finalized_at_height <= chain.height());
    chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .global_beacon_key_sessions
            .insert(id, record);
        transaction
            .world
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, id);
    });
    let counts = pairs
        .iter()
        .map(|_| Arc::new(AtomicUsize::new(0)))
        .collect::<Vec<_>>();
    let keys = pairs
        .iter()
        .map(|pair| PublicKey::new(pair.public_key().try_to_bytes().unwrap().1.to_vec()).unwrap())
        .collect::<Vec<_>>();
    let producers = keys
        .iter()
        .zip(signers)
        .zip(&counts)
        .map(|((key, signer), count)| {
            NativeBeaconProducer::new(
                chain.instance(),
                Some(key.as_bytes().try_into().unwrap()),
                Some(Arc::new(CountedSigner {
                    inner: signer,
                    count: count.clone(),
                })),
            )
        })
        .collect();
    let context = context(&chain);
    Fixture {
        chain,
        keys,
        producers,
        counts,
        context,
    }
}

#[test]
fn all_seats_drive_real_shares_once_and_followers_use_only_transported_pulse() {
    let mut fixture = fixture();
    let source = fixture.chain.state().view();
    let applied = (8, fixture.context.parent_hash);
    let messages = fixture
        .producers
        .iter_mut()
        .map(|producer| ApplicationControl {
            context: fixture.context,
            bytes: producer
                .drive(&source, &fixture.context, applied)
                .unwrap()
                .unwrap(),
        })
        .collect::<Vec<_>>();
    let mut observer = NativeBeaconProducer::new(fixture.chain.instance(), None, None);
    assert!(
        observer
            .drive(&source, &fixture.context, applied)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        observer.build(&build_context(&fixture.context, 0)),
        Err(NativeBeaconError::AwaitingShares { height: 9 })
    ));
    for producer in &fixture.producers {
        assert!(matches!(
            producer.build(&build_context(&fixture.context, 0)),
            Err(NativeBeaconError::AwaitingShares { height: 9 })
        ));
    }
    for (key, message) in fixture.keys.iter().zip(&messages) {
        observer.accept(&source, applied, key, message).unwrap();
        for producer in &mut fixture.producers {
            producer.accept(&source, applied, key, message).unwrap();
        }
    }
    let witness = observer.build(&build_context(&fixture.context, 0)).unwrap();
    assert!(!witness.is_empty());
    assert!(witness.len() < iroha_sumeragi::types::MAX_CONTROL_WITNESS_BYTES);
    let pulse = control::decode(&witness).unwrap().unwrap();
    let mut restarted = NativeBeaconProducer::new(fixture.chain.instance(), None, None);
    for index in [2, 3] {
        restarted
            .accept(&source, applied, &fixture.keys[index], &messages[index])
            .unwrap();
    }
    assert_eq!(
        restarted
            .build(&build_context(&fixture.context, 38))
            .unwrap(),
        witness,
        "a restarted reducer and a different valid threshold subset produce the exact same pulse"
    );
    let partial = control::decode_partial(&messages[0].bytes).unwrap();
    let session = fixture.producers[0]
        .active
        .as_ref()
        .unwrap()
        .aggregator
        .session();
    for mutation in 0..5 {
        let mut changed = pulse.context;
        match mutation {
            0 => changed.instance[0] ^= 1,
            1 => changed.epoch += 1,
            2 => changed.epoch_context_id[0] ^= 1,
            3 => changed.parent_consensus_hash[0] ^= 1,
            _ => changed.parent_result[0] ^= 1,
        }
        let mut foreign = GlobalThresholdBeaconPulseAggregatorV1::new(
            session.clone(),
            pulse.height,
            pulse.finalized_chain_anchor,
            changed,
        )
        .unwrap();
        assert!(
            foreign.accept_partial(partial).is_err(),
            "each complete native context field changes the threshold signing preimage"
        );
        let mut changed_pulse = pulse;
        changed_pulse.context = changed;
        assert!(
            crate::beacon::verify_finalized_global_threshold_beacon_pulse_v1(
                session,
                &changed_pulse,
                pulse.finalized_chain_anchor,
                &changed,
            )
            .is_err(),
            "changing both expected and supplied context cannot reuse the old signature"
        );
    }
    for (index, producer) in fixture.producers.iter_mut().enumerate() {
        assert_eq!(
            producer
                .build(&build_context(&fixture.context, 37))
                .unwrap(),
            witness
        );
        assert_eq!(
            producer.drive(&source, &fixture.context, applied).unwrap(),
            Some(messages[index].bytes)
        );
        assert_eq!(
            fixture.counts[index].load(Ordering::SeqCst),
            1,
            "build and retransmission never sign twice"
        );
    }
    assert_eq!(
        observer
            .accept(&source, applied, &fixture.keys[0], &messages[0])
            .unwrap(),
        IngressOutcome::Duplicate
    );
    control::verify_result(&witness, Some(&pulse)).unwrap();
    assert!(control::verify_result(&witness, None).is_err());
    let current = &source.world().consensus_schedule().ready(9).unwrap().epoch;
    super::super::capture(
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        source.world(),
        source.block_hashes(),
        current,
        9,
        Some(pulse),
        Some(pulse_context(&fixture.context)),
    )
    .unwrap();
    assert!(
        super::super::capture(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            source.world(),
            source.block_hashes(),
            current,
            9,
            None,
            Some(pulse_context(&fixture.context))
        )
        .is_err()
    );
    for mutation in 0..7 {
        let mut altered = pulse;
        match mutation {
            0 => altered.signature[0] ^= 1,
            1 => altered.seed[0] ^= 1,
            2 => altered.height -= 1,
            3 => altered.transcript_hash[0] ^= 1,
            4 => {
                altered.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                    fixture.chain.committed(2).block_hash(),
                )
            }
            5 => {
                altered.finalized_chain_anchor.block_hash = fixture.chain.committed(7).block_hash()
            }
            _ => altered.version ^= 1,
        }
        assert!(
            super::super::capture(
                iroha_data_model::block::consensus::SumeragiRootScope::Global,
                source.world(),
                source.block_hashes(),
                current,
                9,
                Some(altered),
                Some(pulse_context(&fixture.context))
            )
            .is_err()
        );
        assert!(control::verify_result(&witness, Some(&altered)).is_err());
    }
    assert!(
        control::decode(&messages[0].bytes).is_err(),
        "partial is not a finalized pulse frame"
    );
    assert!(control::decode_partial(&witness).is_err());
    let mut trailing = witness;
    trailing.write_all(&[0]).unwrap();
    assert!(control::decode(&trailing).is_err());
    let hashes = (1..=fixture.chain.height())
        .map(|height| fixture.chain.committed(height).block_hash())
        .collect::<Vec<_>>();
    // Restore validation of an NPoS cut additionally requires the live stake owner of every
    // committee seat. Like the session, these rows are explicit component prestate: the
    // fixture's signed genesis registers no staking custody.
    drop(source);
    fixture.chain.setup_world_at(2_000, |transaction| {
        for (peer, _) in fixture.chain.validators() {
            let owner = AccountId::new(peer.public_key().clone());
            transaction.world.public_lane_validators.insert(
                (LaneId::SINGLE, owner.clone()),
                PublicLaneValidatorRecord {
                    lane_id: LaneId::SINGLE,
                    validator: owner.clone(),
                    peer_id: peer.clone(),
                    stake_account: owner,
                    total_stake: Quantity::from(1_000_u32),
                    self_stake: Quantity::from(1_000_u32),
                    metadata: Metadata::default(),
                    status: PublicLaneValidatorStatus::Active,
                    activation_height: 0,
                    election_exit_height: None,
                    deactivation_height: None,
                },
            );
        }
    });
    let source = fixture.chain.state().view();
    crate::state::validator_committee::validate_committed_progress(
        source.world(),
        source.chain_id(),
        fixture.chain.network_id(),
        &hashes,
        fixture.chain.kura(),
        &fixture.chain.state().ivm_execution_budget(),
    )
    .unwrap();
    drop(source);
    fixture.chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .global_beacon_pulses
            .insert(pulse.pulse_id, pulse);
        transaction.world.global_beacon_pulse_slots.insert(
            (
                BeaconSessionId::for_network_v1(&fixture.chain.network_id()),
                pulse.height,
            ),
            pulse.pulse_id,
        );
        transaction.world.global_beacon_latest_pulse.insert(
            GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY,
            crate::beacon::validate_persisted_global_threshold_beacon_pulse_v1(&pulse).unwrap(),
        );
    });
    let source = fixture.chain.state().view();
    let error = crate::state::validator_committee::validate_committed_progress(
        source.world(),
        source.chain_id(),
        fixture.chain.network_id(),
        &hashes,
        fixture.chain.kura(),
        &fixture.chain.state().ivm_execution_budget(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        crate::execution_attempt::ExecutionAttemptError::Rejected(
            "restored beacon history adds or omits certified native pulse work".to_owned()
        )
    );
}

#[test]
fn wrong_source_sender_and_proof_never_change_the_owned_round() {
    let mut fixture = fixture();
    let source = fixture.chain.state().view();
    let applied = (8, fixture.context.parent_hash);
    let own = fixture.producers[0]
        .drive(&source, &fixture.context, applied)
        .unwrap()
        .unwrap();
    for mutation in 0..6 {
        let mut wrong = fixture.context;
        match mutation {
            0 => wrong.instance.0[0] ^= 1,
            1 => wrong.height += 1,
            2 => wrong.epoch.epoch += 1,
            3 => wrong.epoch.context.0[0] ^= 1,
            4 => wrong.parent_hash.0[0] ^= 1,
            _ => wrong.parent_result.0[0] ^= 1,
        }
        assert!(
            fixture.producers[0]
                .drive(&source, &wrong, applied)
                .is_err()
        );
        assert_eq!(
            fixture.producers[0]
                .drive(&source, &fixture.context, applied)
                .unwrap(),
            Some(own)
        );
    }
    assert!(
        fixture.producers[0]
            .drive(&source, &fixture.context, (7, applied.1))
            .is_err()
    );
    let other = ApplicationControl {
        context: fixture.context,
        bytes: fixture.producers[1]
            .drive(&source, &fixture.context, applied)
            .unwrap()
            .unwrap(),
    };
    assert!(matches!(
        fixture.producers[0].accept(&source, applied, &fixture.keys[2], &other),
        Err(NativeBeaconError::Sender)
    ));
    let mut partial = control::decode_partial(&other.bytes).unwrap();
    partial.signature_share[0] ^= 1;
    let bad = ApplicationControl {
        context: fixture.context,
        bytes: control::encode_partial(&partial).unwrap(),
    };
    assert!(
        fixture.producers[0]
            .accept(&source, applied, &fixture.keys[1], &bad)
            .is_err()
    );
    assert!(matches!(
        fixture.producers[0].build(&build_context(&fixture.context, 0)),
        Err(NativeBeaconError::AwaitingShares { .. })
    ));
    assert_eq!(
        fixture.producers[0]
            .accept(&source, applied, &fixture.keys[1], &other)
            .unwrap(),
        IngressOutcome::Finalized
    );
    assert_eq!(fixture.counts[0].load(Ordering::SeqCst), 1);
}

#[test]
fn explicitly_anchored_no_demand_needs_neither_session_nor_fake_observer_key() {
    let chain = prefix();
    let context = context(&chain);
    let source = chain.state().view();
    let mut observer = NativeBeaconProducer::new(chain.instance(), None, None);
    assert!(
        observer.build(&build_context(&context, 0)).is_err(),
        "no unanchored empty default"
    );
    assert!(
        observer
            .drive(&source, &context, (8, context.parent_hash))
            .unwrap()
            .is_none()
    );
    let witness = observer.build(&build_context(&context, 5)).unwrap();
    assert!(witness.is_empty());
    assert_eq!(control::decode(&witness).unwrap(), None);
    control::verify_result(&witness, None).unwrap();
    let current = &source.world().consensus_schedule().ready(9).unwrap().epoch;
    super::super::capture(
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        source.world(),
        source.block_hashes(),
        current,
        9,
        None,
        Some(pulse_context(&context)),
    )
    .unwrap();
}

#[test]
fn refusal_classification_keeps_remote_faults_out_of_local_recovery() {
    use NativeControlFailure::{RecoveryRequired, Rejected, Retryable};
    assert_eq!(
        NativeBeaconError::Context.ingress_classification(),
        Rejected
    );
    assert_eq!(NativeBeaconError::Context.local_classification(), Retryable);
    assert_eq!(NativeBeaconError::Sender.ingress_classification(), Rejected);
    assert_eq!(
        NativeBeaconError::LocalSigning.local_classification(),
        Retryable
    );
    assert_eq!(
        NativeBeaconError::AwaitingShares { height: 9 }.local_classification(),
        Retryable
    );
    let source = NativeBeaconError::Source("claimed applied parent is missing".into());
    assert_eq!(source.local_classification(), RecoveryRequired);
    assert_eq!(source.ingress_classification(), RecoveryRequired);
    let malformed = NativeBeaconError::Codec(control::ControlCodecError::ResultMismatch);
    assert_eq!(malformed.ingress_classification(), Rejected);
    assert_eq!(malformed.local_classification(), RecoveryRequired);
}

struct FaultSigner {
    inner: Arc<dyn GlobalThresholdBeaconPartialSignerV1>,
    attempts: Arc<AtomicUsize>,
    corrupt: bool,
}
impl GlobalThresholdBeaconPartialSignerV1 for FaultSigner {
    fn attest_partial_signing_capability(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        expected_signer_index: u16,
    ) -> Result<
        GlobalThresholdBeaconPartialSigningCapabilityV1,
        GlobalThresholdBeaconCapabilityErrorV1,
    > {
        self.inner
            .attest_partial_signing_capability(session, expected_signer_index)
    }
    fn sign_partial(
        &self,
        session: &ValidatedGlobalThresholdBeaconSessionV1,
        payload: &[u8],
    ) -> Result<GlobalThresholdBeaconPartialSignatureV1, String> {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
        if !self.corrupt && attempt == 0 {
            return Err("explicit transient component signer refusal".into());
        }
        let mut partial = self.inner.sign_partial(session, payload)?;
        if self.corrupt {
            partial.signature_share[0] ^= 1;
        }
        Ok(partial)
    }
}

#[test]
fn native_invalid_local_share_is_never_retained_or_counted() {
    let mut fixture = fixture();
    let attempts = Arc::new(AtomicUsize::new(0));
    let signer = fixture.producers[0].signer.take().unwrap();
    fixture.producers[0].signer = Some(Arc::new(FaultSigner {
        inner: signer,
        attempts: attempts.clone(),
        corrupt: true,
    }));
    let source = fixture.chain.state().view();
    let applied = (8, fixture.context.parent_hash);
    assert!(matches!(
        fixture.producers[0].drive(&source, &fixture.context, applied),
        Err(NativeBeaconError::LocalSigning)
    ));
    let active = fixture.producers[0].active.as_ref().unwrap();
    assert!(active.own.is_none());
    assert!(active.finalized.is_none());
    let payload = active.aggregator.payload().as_ptr();
    let remote = ApplicationControl {
        context: fixture.context,
        bytes: fixture.producers[1]
            .drive(&source, &fixture.context, applied)
            .unwrap()
            .unwrap(),
    };
    assert_eq!(
        fixture.producers[0]
            .accept(&source, applied, &fixture.keys[1], &remote)
            .unwrap(),
        IngressOutcome::Accepted,
        "one remote share cannot combine with an invalid local share"
    );
    assert!(matches!(
        fixture.producers[0].build(&build_context(&fixture.context, 0)),
        Err(NativeBeaconError::AwaitingShares { height: 9 })
    ));
    assert!(matches!(
        fixture.producers[0].drive(&source, &fixture.context, applied),
        Err(NativeBeaconError::LocalSigning)
    ));
    let active = fixture.producers[0].active.as_ref().unwrap();
    assert_eq!(active.aggregator.payload().as_ptr(), payload);
    assert!(active.own.is_none());
    assert!(active.finalized.is_none());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let mut bad = control::decode_partial(&remote.bytes).unwrap();
    bad.signature_share[0] ^= 1;
    assert!(
        fixture.producers[0]
            .accept(
                &source,
                applied,
                &fixture.keys[1],
                &ApplicationControl {
                    context: fixture.context,
                    bytes: control::encode_partial(&bad).unwrap(),
                }
            )
            .is_err()
    );
}

#[test]
fn native_transient_signer_refusal_retains_remote_progress_and_exact_retry_payload() {
    let mut fixture = fixture();
    let attempts = Arc::new(AtomicUsize::new(0));
    let signer = fixture.producers[0].signer.take().unwrap();
    fixture.producers[0].signer = Some(Arc::new(FaultSigner {
        inner: signer,
        attempts: attempts.clone(),
        corrupt: false,
    }));
    let source = fixture.chain.state().view();
    let applied = (8, fixture.context.parent_hash);
    assert!(matches!(
        fixture.producers[0].drive(&source, &fixture.context, applied),
        Err(NativeBeaconError::LocalSigning)
    ));
    let active = fixture.producers[0].active.as_ref().unwrap();
    let original_payload = active.aggregator.payload().as_ptr();
    assert!(active.own.is_none());
    let remote = ApplicationControl {
        context: fixture.context,
        bytes: fixture.producers[1]
            .drive(&source, &fixture.context, applied)
            .unwrap()
            .unwrap(),
    };
    assert_eq!(
        fixture.producers[0]
            .accept(&source, applied, &fixture.keys[1], &remote)
            .unwrap(),
        IngressOutcome::Accepted
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "incoming authentic progress does not rerun a failed local signer"
    );
    let own = fixture.producers[0]
        .drive(&source, &fixture.context, applied)
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture.producers[0]
            .active
            .as_ref()
            .unwrap()
            .aggregator
            .payload()
            .as_ptr(),
        original_payload
    );
    let finalized = fixture.producers[0]
        .build(&build_context(&fixture.context, 0))
        .unwrap();
    assert!(!finalized.is_empty());
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.producers[0]
            .drive(&source, &fixture.context, applied)
            .unwrap(),
        Some(own)
    );
    assert_eq!(
        fixture.producers[0]
            .build(&build_context(&fixture.context, 37))
            .unwrap(),
        finalized
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.producers[0]
            .accept(&source, applied, &fixture.keys[1], &remote)
            .unwrap(),
        IngressOutcome::Duplicate
    );
}

#[test]
fn native_mandatory_slot_starts_without_transaction_work_and_missing_key_refuses() {
    let mut fixture = fixture();
    assert!(
        fixture
            .counts
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 0)
    );
    let source = fixture.chain.state().view();
    let applied = (8, fixture.context.parent_hash);
    let own = fixture.producers[0]
        .drive(&source, &fixture.context, applied)
        .unwrap();
    assert!(
        own.is_some(),
        "mandatory control work must make progress even without user transactions"
    );
    assert_eq!(fixture.counts[0].load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture.producers[0].build(&build_context(&fixture.context, 0)),
        Err(NativeBeaconError::AwaitingShares { height: 9 })
    ));
    drop(source);
    fixture.chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .global_beacon_active_session
            .remove(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY);
    });
    let source = fixture.chain.state().view();
    for producer in &mut fixture.producers[1..] {
        assert!(matches!(
            producer.drive(&source, &fixture.context, applied),
            Err(NativeBeaconError::Source(_))
        ));
        assert!(producer.active.is_none());
        assert!(producer.build(&build_context(&fixture.context, 0)).is_err());
    }
    assert!(
        fixture.counts[1..]
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 0)
    );
}

#[test]
fn native_active_session_from_a_foreign_real_committee_refuses_before_signing() {
    let mut fixture = fixture();
    let mut pairs = (0xD1..=0xD4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    pairs.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let peers = pairs
        .iter()
        .map(|pair| iroha_model_base::peer::PeerId::new(pair.public_key().clone()))
        .collect::<Vec<_>>();
    let id: [u8; 32] = Hash::new(b"foreign native beacon roster").into();
    let generation = fixture
        .chain
        .state()
        .view()
        .world()
        .consensus_schedule()
        .ready(9)
        .unwrap()
        .epoch
        .authorization
        .authority_generation;
    let (session, _) = prepared_session_and_signers_fixture_for_keys_v1(
        GlobalThresholdBeaconDkgSessionV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id: fixture.chain.network_id(),
            session_id: id,
            attempt_id: id,
            authority_generation: generation,
            roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&peers),
            committee_size: 4,
            threshold: 2,
            start_height: 1,
            commitments_end_height: 2,
            deliveries_end_height: 3,
            acceptances_end_height: 4,
        },
        &pairs,
        &fixture.chain.state().ivm_execution_budget(),
    );
    let mut record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        session: session.clone(),
        activated_at_height: None,
        retired_at_height: None,
    };
    record
        .activate(session.record().adaptive_dkg.finalized_at_height)
        .unwrap();
    fixture.chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .global_beacon_key_sessions
            .insert(id, record);
        transaction
            .world
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, id);
    });
    let source = fixture.chain.state().view();
    let applied = (8, fixture.context.parent_hash);
    for producer in &mut fixture.producers {
        assert!(matches!(
            producer.drive(&source, &fixture.context, applied),
            Err(NativeBeaconError::Source(_))
        ));
        assert!(producer.active.is_none());
        assert!(producer.build(&build_context(&fixture.context, 0)).is_err());
    }
    assert!(
        fixture
            .counts
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 0)
    );
}

#[test]
fn valid_same_roster_foreign_generation_refuses_production_readiness_and_capture() {
    let mut fixture = fixture();
    let mut pairs = (0xC1..=0xC4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    pairs.sort_by(|left, right| left.public_key().cmp(right.public_key()));
    let peers = pairs
        .iter()
        .map(|pair| iroha_model_base::peer::PeerId::new(pair.public_key().clone()))
        .collect::<Vec<_>>();
    let (original_id, current_generation) = {
        let view = fixture.chain.state().view();
        let retained = view.world().consensus_schedule();
        let current = &retained.ready(9).unwrap().epoch;
        assert_eq!(
            peers,
            current
                .committee
                .iter()
                .map(|seat| seat.validator.clone())
                .collect::<Vec<_>>()
        );
        (
            view.world().active_global_beacon_key_session().unwrap(),
            current.authorization.authority_generation,
        )
    };
    let id: [u8; 32] = Hash::new(b"same roster foreign native beacon generation").into();
    let (session, signers) = prepared_session_and_signers_fixture_for_keys_v1(
        GlobalThresholdBeaconDkgSessionV1 {
            version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
            network_id: fixture.chain.network_id(),
            session_id: id,
            attempt_id: id,
            authority_generation: current_generation.checked_add(1).unwrap(),
            roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&peers),
            committee_size: 4,
            threshold: 2,
            start_height: 1,
            commitments_end_height: 2,
            deliveries_end_height: 3,
            acceptances_end_height: 4,
        },
        &pairs,
        &fixture.chain.state().ivm_execution_budget(),
    );
    let anchor = GlobalThresholdBeaconChainAnchorV1 {
        height: 8,
        block_hash: fixture.chain.committed(8).block_hash(),
    };
    // This is a real threshold proof under the original network and BLS roster;
    // only the generation lacks the incumbent epoch's authorization.
    let mut aggregator = GlobalThresholdBeaconPulseAggregatorV1::new(
        session.clone(),
        9,
        anchor,
        pulse_context(&fixture.context),
    )
    .unwrap();
    for signer in signers.iter().take(2) {
        let partial = signer.sign_partial(&session, aggregator.payload()).unwrap();
        aggregator.accept_partial(partial).unwrap();
    }
    let pulse = aggregator.finalize().unwrap();
    crate::beacon::verify_finalized_global_threshold_beacon_pulse_v1(
        &session,
        &pulse,
        anchor,
        &pulse_context(&fixture.context),
    )
    .unwrap();
    let mut record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        session,
        activated_at_height: None,
        retired_at_height: None,
    };
    record
        .activate(record.session.adaptive_dkg.finalized_at_height)
        .unwrap();
    fixture.chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .global_beacon_key_sessions
            .insert(id, record);
        transaction
            .world
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, id);
    });
    let state = fixture.chain.state();
    let generation = state.state_view_generation();
    let report = fixture.producers[0]
        .attach_readiness(&state.ivm_execution_budget())
        .unwrap();
    let applied = (8, fixture.context.parent_hash);
    {
        let source = state.view();
        for producer in &mut fixture.producers {
            let error = producer
                .drive(&source, &fixture.context, applied)
                .unwrap_err();
            assert!(
                matches!(&error, NativeBeaconError::Source(message)
                    if message.contains("active session differs from the authenticated epoch")),
                "{error}"
            );
            assert!(producer.active.is_none());
            assert!(producer.build(&build_context(&fixture.context, 0)).is_err());
        }
        fixture.producers[0]
            .refresh_readiness(&source, &fixture.context, applied, generation)
            .unwrap();
        let (horizon, ready) = report.read(generation, 9, 8).unwrap();
        assert!(!ready && !horizon.session_covers_next_pulse && !horizon.local_provider_ready);
        let retained = source.world().consensus_schedule();
        let current = &retained.ready(9).unwrap().epoch;
        let error = super::super::capture(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
            source.world(),
            source.block_hashes(),
            current,
            9,
            Some(pulse),
            Some(pulse_context(&fixture.context)),
        )
        .unwrap_err();
        assert!(error.contains("authorized generation"), "{error}");
        assert_eq!(source.world().active_global_beacon_key_session(), Some(id));
        assert!(
            source
                .world()
                .global_beacon_pulses()
                .get(&pulse.pulse_id)
                .is_none()
        );
    }
    assert!(
        fixture
            .counts
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 0),
        "a valid foreign-generation proof never authorizes local signing"
    );
    fixture.chain.setup_world_at(2_001, |transaction| {
        transaction
            .world
            .global_beacon_active_session
            .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, original_id);
    });
    let state = fixture.chain.state();
    let generation = state.state_view_generation();
    let source = state.view();
    fixture.producers[0]
        .refresh_readiness(&source, &fixture.context, applied, generation)
        .unwrap();
    assert!(report.read(generation, 9, 8).unwrap().1);
    assert!(
        fixture.producers[0]
            .drive(&source, &fixture.context, applied)
            .unwrap()
            .is_some()
    );
    assert_eq!(fixture.counts[0].load(Ordering::SeqCst), 1);
}

#[test]
fn readiness_reprobes_same_applied_cut_without_signing_and_excludes_stale_generation() {
    let mut fixture = fixture();
    let state = fixture.chain.state();
    let generation = state.state_view_generation();
    let budget = state.ivm_execution_budget();
    let reporting = fixture.producers[0].attach_readiness(&budget).unwrap();
    assert!(reporting.read(generation, 9, 8).is_none());
    let view = state.view();
    fixture.producers[0]
        .refresh_readiness(
            &view,
            &fixture.context,
            (8, fixture.context.parent_hash),
            generation,
        )
        .unwrap();
    let (horizon, ready) = reporting.read(generation, 9, 8).unwrap();
    assert!(ready && horizon.local_provider_ready && horizon.session_covers_next_pulse);
    assert_eq!(horizon.next_required_pulse_height, Some(9));
    assert_eq!(horizon.epoch_length_blocks, NPOS_EPOCH_LENGTH_BLOCKS);
    assert_eq!(
        fixture.counts[0].load(Ordering::SeqCst),
        0,
        "readiness never signs a partial"
    );
    let signer = fixture.producers[0].signer.take();
    fixture.producers[0]
        .refresh_readiness(
            &view,
            &fixture.context,
            (8, fixture.context.parent_hash),
            generation,
        )
        .unwrap();
    let (unavailable, ready) = reporting.read(generation, 9, 8).unwrap();
    assert!(!ready && !unavailable.local_provider_ready);
    assert_eq!(unavailable.active_session_id, horizon.active_session_id);
    fixture.producers[0].signer = signer;
    fixture.producers[0]
        .refresh_readiness(
            &view,
            &fixture.context,
            (8, fixture.context.parent_hash),
            generation,
        )
        .unwrap();
    assert!(reporting.read(generation, 9, 8).unwrap().1);
    assert!(reporting.read(generation + 2, 9, 8).is_none());
    assert!(reporting.read(generation, 10, 8).is_none());
    assert!(reporting.read(generation, 9, 7).is_none());
    let mut observer = NativeBeaconProducer::new(fixture.chain.instance(), None, None);
    let report = observer.attach_readiness(&budget).unwrap();
    observer
        .refresh_readiness(
            &view,
            &fixture.context,
            (8, fixture.context.parent_hash),
            generation,
        )
        .unwrap();
    let (horizon, ready) = report.read(generation, 9, 8).unwrap();
    assert!(ready && !horizon.local_provider_ready);
    assert_eq!(
        fixture.chain.height(),
        8,
        "readiness recovery requires no extra block"
    );
}

#[test]
fn readiness_no_demand_does_not_require_a_beacon_session() {
    let chain = prefix();
    let context = context(&chain);
    let state = chain.state();
    let generation = state.state_view_generation();
    let key: [u8; 48] = chain.validators()[0]
        .0
        .public_key()
        .try_to_bytes()
        .unwrap()
        .1
        .try_into()
        .unwrap();
    let mut producer = NativeBeaconProducer::new(chain.instance(), Some(key), None);
    let report = producer
        .attach_readiness(&state.ivm_execution_budget())
        .unwrap();
    producer
        .refresh_readiness(
            &state.view(),
            &context,
            (8, context.parent_hash),
            generation,
        )
        .unwrap();
    let (horizon, ready) = report.read(generation, 9, 8).unwrap();
    assert!(ready);
    assert_eq!(horizon.next_required_pulse_height, None);
    assert_eq!(horizon.active_session_id, None);
    assert!(!horizon.local_provider_ready);
}

/// Parliament admission, kept apart from the generic NPoS fixture above.
///
/// On a Permissioned chain (no native pulse cadence) a canonically admitted Parliament
/// sortition attempt derives its governance-local slot index and nothing else: consensus
/// demands no pulse for the slot, the readiness horizon has no height, and the producer
/// neither signs nor waits for shares.
#[test]
fn parliament_attempt_admission_derives_the_slot_index_and_no_pulse_demand() {
    let mut fixture = seeded(prefix());
    let chain = &fixture.chain;
    let roster = chain
        .validators()
        .iter()
        .map(|(peer, _)| peer.clone())
        .collect::<Vec<_>>();
    let applied = (8, fixture.context.parent_hash);
    {
        let view = chain.state().view();
        let retained = view.world().consensus_schedule();
        let current = &retained.ready(9).unwrap().epoch;
        assert_eq!(current.mode, ConsensusMode::Permissioned);
        assert!(
            !super::super::required(SumeragiRootScope::Global, view.world(), current, 9).unwrap(),
            "a Permissioned chain without an admitted attempt has no demand"
        );
    }
    let (attempt_id, _, attempt) =
        crate::beacon::tests::pending_batched_sortition_attempt(&chain.network_id(), &roster, 9);
    chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .put_parliament_attempt(attempt)
            .expect("admit the producer's Parliament demand");
        assert_eq!(
            transaction
                .world
                .parliament_required_beacon_pulse_slots
                .get(&(BeaconSessionId::for_network_v1(&chain.network_id()), 9)),
            Some(&BTreeSet::from([attempt_id]))
        );
    });
    let state = chain.state();
    let generation = state.state_view_generation();
    let view = state.view();
    {
        let retained = view.world().consensus_schedule();
        let current = &retained.ready(9).unwrap().epoch;
        assert!(
            !super::super::required(SumeragiRootScope::Global, view.world(), current, 9).unwrap(),
            "the admitted governance slot creates no consensus demand"
        );
    }
    let reporting = fixture.producers[0]
        .attach_readiness(&state.ivm_execution_budget())
        .unwrap();
    fixture.producers[0]
        .refresh_readiness(&view, &fixture.context, applied, generation)
        .unwrap();
    let (horizon, ready) = reporting.read(generation, 9, 8).unwrap();
    assert!(ready, "no demand remains, so custody is not required");
    assert_eq!(horizon.epoch_length_blocks, 0);
    assert_eq!(
        horizon.next_required_pulse_height, None,
        "the horizon has no Parliament-derived height"
    );
    assert!(!horizon.session_covers_next_pulse);
    for producer in &mut fixture.producers {
        assert!(
            producer
                .drive(&view, &fixture.context, applied)
                .unwrap()
                .is_none(),
            "no signing round opens for a governance slot"
        );
        assert!(producer.active.is_none());
        assert!(
            producer
                .build(&build_context(&fixture.context, 0))
                .unwrap()
                .is_empty(),
            "the control witness is empty instead of waiting for shares"
        );
    }
    assert!(
        fixture
            .counts
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 0),
        "no seat signs a partial for a governance slot"
    );
}

/// The readiness horizon is consensus-native only. A pending governance slot at a height that
/// is not this chain's native pulse height never becomes the next required pulse, and on a
/// Permissioned root governance state makes no validator depend on beacon custody.
#[test]
fn readiness_horizon_is_native_only_with_pending_parliament_slots() {
    // NPoS, mid-epoch: tip 5, native pulse at 9, a governance slot awaited at 7.
    let chain = npos_prefix(5);
    let npos_context = context(&chain);
    assert_eq!(npos_context.height, 6);
    let roster = chain
        .validators()
        .iter()
        .map(|(peer, _)| peer.clone())
        .collect::<Vec<_>>();
    let key: [u8; 48] = roster[0]
        .public_key()
        .try_to_bytes()
        .unwrap()
        .1
        .try_into()
        .unwrap();
    // The attempt froze another epoch length, so its slot 7 is an ordinary height here, as a
    // timed-OVN release height is.
    let (attempt_id, _, attempt) =
        crate::beacon::tests::pending_batched_sortition_attempt(&chain.network_id(), &roster, 7);
    let slot = (BeaconSessionId::for_network_v1(&chain.network_id()), 7);
    chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .put_parliament_attempt(attempt)
            .expect("admit the pending governance slot");
    });
    let state = chain.state();
    let generation = state.state_view_generation();
    let view = state.view();
    assert_eq!(
        view.world()
            .parliament_required_beacon_pulse_slots()
            .get(&slot),
        Some(&BTreeSet::from([attempt_id]))
    );
    {
        let retained = view.world().consensus_schedule();
        let current = &retained.ready(6).unwrap().epoch;
        assert_eq!(current.mode, ConsensusMode::Npos);
        for height in 6..=10 {
            assert_eq!(
                super::super::required(SumeragiRootScope::Global, view.world(), current, height)
                    .unwrap(),
                height == 9,
                "only the pre-boundary height {height} == 9 is demanded"
            );
        }
    }
    let mut validator = NativeBeaconProducer::new(chain.instance(), Some(key), None);
    let report = validator
        .attach_readiness(&state.ivm_execution_budget())
        .unwrap();
    validator
        .refresh_readiness(
            &view,
            &npos_context,
            (5, npos_context.parent_hash),
            generation,
        )
        .unwrap();
    let (horizon, ready) = report.read(generation, 6, 5).unwrap();
    assert_eq!(horizon.epoch_length_blocks, NPOS_EPOCH_LENGTH_BLOCKS);
    assert_eq!(
        horizon.next_required_pulse_height,
        Some(9),
        "the native boundary pulse, not the governance slot at 7"
    );
    assert!(
        !ready,
        "the native obligation still needs custody; governance state did not create it"
    );
    assert!(
        validator
            .drive(&view, &npos_context, (5, npos_context.parent_hash))
            .unwrap()
            .is_none()
            && validator.active.is_none(),
        "height 6 opens no round"
    );
    drop(view);

    // Permissioned: the same kind of pending slot at the next height, and no session at all.
    let chain = prefix();
    let context = context(&chain);
    let roster = chain
        .validators()
        .iter()
        .map(|(peer, _)| peer.clone())
        .collect::<Vec<_>>();
    let key: [u8; 48] = roster[0]
        .public_key()
        .try_to_bytes()
        .unwrap()
        .1
        .try_into()
        .unwrap();
    let (attempt_id, _, attempt) =
        crate::beacon::tests::pending_batched_sortition_attempt(&chain.network_id(), &roster, 9);
    chain.setup_world_at(2_000, |transaction| {
        transaction
            .world
            .put_parliament_attempt(attempt)
            .expect("admit the pending governance slot");
    });
    let state = chain.state();
    let generation = state.state_view_generation();
    let view = state.view();
    assert_eq!(
        view.world()
            .parliament_required_beacon_pulse_slots()
            .get(&(BeaconSessionId::for_network_v1(&chain.network_id()), 9)),
        Some(&BTreeSet::from([attempt_id]))
    );
    assert!(view.world().active_global_beacon_key_session().is_none());
    let mut validator = NativeBeaconProducer::new(chain.instance(), Some(key), None);
    let report = validator
        .attach_readiness(&state.ivm_execution_budget())
        .unwrap();
    validator
        .refresh_readiness(&view, &context, (8, context.parent_hash), generation)
        .unwrap();
    let (horizon, ready) = report.read(generation, 9, 8).unwrap();
    assert!(
        ready,
        "a validator without beacon custody is ready: Parliament state demands none"
    );
    assert_eq!(horizon.next_required_pulse_height, None);
    assert_eq!(horizon.active_session_id, None);
    assert!(!horizon.local_provider_ready && !horizon.session_covers_next_pulse);
}

#[path = "execution_tests.rs"]
mod execution_tests;

#[test]
fn control_retries_use_original_tip_without_decoding_history_again() {
    let chain = prefix();
    let context = context(&chain);
    let state = chain.state();
    let view = state.view();
    let generation = state.state_view_generation();
    let mut producer = NativeBeaconProducer::new(chain.instance(), None, None);
    let report = producer
        .attach_readiness(&state.ivm_execution_budget())
        .unwrap();
    let (_, observed) = crate::sumeragi::certified_chain::relation_counts::measure(|| {
        for _ in 0..3 {
            producer
                .refresh_readiness(&view, &context, (8, context.parent_hash), generation)
                .unwrap();
            assert!(report.read(generation, 9, 8).unwrap().1);
            assert!(
                producer
                    .drive(&view, &context, (8, context.parent_hash))
                    .unwrap()
                    .is_none()
            );
        }
    });
    assert!(
        observed.frames.is_empty(),
        "current-tip control redecoded durable history: {observed:?}"
    );
    assert!(
        observed.qcs.is_empty(),
        "current-tip control consulted a local quorum"
    );
}

#[test]
fn control_requires_original_tip_and_matching_published_hash_journal() {
    let chain = prefix();
    let context = context(&chain);
    let state = chain.state();
    let mut producer = NativeBeaconProducer::new(chain.instance(), None, None);
    let report = producer
        .attach_readiness(&state.ivm_execution_budget())
        .unwrap();
    let generation = state.state_view_generation();
    let applied = (8, context.parent_hash);
    producer
        .refresh_readiness(&state.view(), &context, applied, generation)
        .unwrap();
    assert!(report.read(generation, 9, 8).unwrap().1);

    // A matching journal is still only a claim without its original execution tip.
    let unanchored = crate::state::State::new_for_testing(
        World::new(),
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
    );
    let mut hashes = unanchored.block_hashes.block();
    for hash in state.view().block_hashes().iter() {
        hashes.push_for_tests(*hash);
    }
    hashes.commit_for_tests();
    assert_eq!(unanchored.view().height(), 8);
    assert!(unanchored.view().native_execution_tip().is_none());
    assert!(
        producer
            .drive(&unanchored.view(), &context, applied)
            .is_err()
    );
    assert!(
        producer
            .refresh_readiness(&unanchored.view(), &context, applied, generation)
            .is_err()
    );
    assert!(report.read(generation, 9, 8).is_none());

    producer
        .refresh_readiness(&state.view(), &context, applied, generation)
        .unwrap();
    assert!(report.read(generation, 9, 8).unwrap().1);

    // Keep the real tip and height, but replace the journal's last hash. Neither
    // control production nor readiness may combine different publication cuts.
    let original_tip = state.view().native_execution_tip().unwrap();
    let mut hashes = state.block_hashes.block_and_revert();
    hashes.push_for_tests(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
        b"foreign control parent",
    )));
    hashes.commit_for_tests();
    let view = state.view();
    assert_eq!(view.height(), 8);
    assert_eq!(view.native_execution_tip(), Some(original_tip));
    assert_ne!(view.block_hashes().last(), Some(&original_tip.iroha_hash()));
    assert!(matches!(
        producer.drive(&view, &context, applied),
        Err(NativeBeaconError::Source(_))
    ));
    assert!(
        producer
            .refresh_readiness(&view, &context, applied, generation)
            .is_err()
    );
    assert!(report.read(generation, 9, 8).is_none());
    assert!(
        producer.active.is_none(),
        "a rejected source cannot begin signing"
    );
}
