//! The lane merge end to end on a certified test chain: a genesis lane policy creates a fixed
//! lane, certified lane blocks land in the node's lane store, and the chain's blocks merge them.

use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};

use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Level, Registrable,
    account::{Account, AccountId},
    isi::{InstructionBox, Log},
    parameter::{Parameter, system::SumeragiParameters},
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLaneRecord, SumeragiLaneRoute,
    },
};
use iroha_model_base::topology::DataSpaceId;
use iroha_sumeragi::{
    api::ExecOutcome,
    availability::{PayloadAuthoring, PayloadBytes},
    crypto::{Signer, form_qc},
    message::{BlockHeader, Vote, VoteKind},
    preimage::payload_hash,
    types::{SIGNATURE_LEN, Signature},
};

use super::*;
use crate::{
    state::World,
    sumeragi::{
        crypto::{BlsCrypto, KeyPairSigner},
        driver::{
            SharedCrypto,
            traits::{BlockStore as _, Executor as _},
        },
        lanes::{
            executor::{LaneExecutor, LaneTransactions},
            global::{AppliedWatch, GlobalAnchors, StatelessChecks},
        },
        payload::{self, Assembly},
        test_chain::{CertifiedTestChain, TestChainConfig, fixture_validators},
    },
};

const LANE: LaneId = LaneId::new(2);
const GENESIS_MS: u64 = 10_000;

/// The lane stores, bound once the chain (and so its network id) exists.
#[derive(Default)]
struct Deferred(OnceLock<Arc<super::super::registry::LaneStores>>);

impl LaneBlockSource for Deferred {
    fn tip(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
    ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        self.0
            .get()
            .map_or(Ok(None), |stores| stores.tip(lane, incarnation))
    }
    fn block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
    ) -> Result<
        Option<CommittedLaneBlock>,
        crate::execution_attempt::ExecutionAttemptError<std::io::Error>,
    > {
        self.0
            .get()
            .map_or(Ok(None), |stores| stores.block(lane, incarnation, height))
    }
    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        timeout: Duration,
    ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
        self.0.get().map_or(Ok(false), |stores| {
            stores.wait_for(lane, incarnation, height, timeout)
        })
    }
}

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

/// Transactions of this account route to the fixed lane.
fn lane_user() -> KeyPair {
    key(0x51)
}

/// Transactions of this account take the default route (lane 0).
fn other_user() -> KeyPair {
    key(0x52)
}

fn policy() -> SumeragiLanePolicy {
    SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 4,
        max_merge_blocks: 8,
        stall_window: 1_000,
        lane_params: SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: LANE,
            dataspace: DataSpaceId::new(0),
            committee: fixture_validators()
                .into_iter()
                .map(|(peer, pop)| SumeragiLaneMember { peer, pop })
                .collect(),
        }],
        routes: vec![SumeragiLaneRoute {
            lane: LANE,
            account: Some(AccountId::new(lane_user().public_key().clone()).to_string()),
            instruction: None,
        }],
        autoscale: None,
    }
}

struct NoTransactions;
impl LaneTransactions for NoTransactions {
    fn candidates(
        &self,
        _: u64,
        _: usize,
        _: &BTreeSet<HashOf<TransactionEntrypoint>>,
    ) -> Result<Vec<SignedTransaction>, crate::execution_attempt::ExecutionDeferred> {
        Ok(Vec::new())
    }
}

struct Fixture {
    chain: CertifiedTestChain,
    keys: Vec<KeyPair>,
    stores: Arc<super::super::registry::LaneStores>,
    crypto: SharedCrypto,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn start() -> Self {
        Self::start_with_policy_and_configure(policy(), |_| {})
    }

    fn start_with_policy_and_configure(
        policy: SumeragiLanePolicy,
        configure: impl FnOnce(&mut TestChainConfig),
    ) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut world = World::default();
        for key in [lane_user(), other_user()] {
            let id = AccountId::new(key.public_key().clone());
            let (id, value) = Account::new(id.clone()).build(&id).into_key_value();
            world.accounts.insert(id, value);
        }
        let deferred = Arc::new(Deferred::default());
        let mut config = TestChainConfig::new(world, GENESIS_MS);
        config
            .genesis_parameters
            .push(Parameter::Custom(policy.into_custom_parameter()));
        config.lane_blocks = deferred.clone();
        configure(&mut config);
        let prepared = CertifiedTestChain::prepare(config).expect("original signed genesis");
        let keys = prepared.validator_keys.clone();
        let chain = CertifiedTestChain::from_prepared(prepared).expect("the chain starts");
        let bls = Arc::new(BlsCrypto::new());
        let crypto: SharedCrypto = bls.clone();
        let stores = Arc::new(super::super::registry::LaneStores::new(
            dir.path().to_path_buf(),
            chain.network_id(),
            chain.state().view().chain_id().to_string(),
            Arc::clone(&crypto),
            chain.state().ivm_execution_budget(),
            Arc::new(crate::sumeragi::test_chain::TestLaneStoreAuthorities::new(
                Arc::clone(chain.state()),
                bls,
            )),
        ));
        assert!(deferred.0.set(Arc::clone(&stores)).is_ok());
        Self {
            chain,
            keys,
            stores,
            crypto,
            _dir: dir,
        }
    }

    fn record(&self) -> SumeragiLaneRecord {
        self.chain
            .state()
            .view()
            .world()
            .sumeragi_lanes()
            .lane(LANE)
            .cloned()
            .expect("the fixed lane exists")
    }

    fn anchor(&self, height: u64) -> iroha_crypto::HashOf<iroha_data_model::block::BlockHeader> {
        let view = self.chain.state().view();
        view.block_hashes()
            .iter()
            .nth(usize::try_from(height - 1).expect("small"))
            .copied()
            .expect("an applied anchor")
    }

    fn log(&self, key: &KeyPair, text: &str, created_ms: u64) -> SignedTransaction {
        self.chain.sign(
            key,
            [InstructionBox::from(Log::new(Level::INFO, text.to_owned()))],
            created_ms,
        )
    }

    /// Store a certified lane block at `height` carrying `transactions` anchored at `anchor`.
    fn certify(&self, height: u64, anchor: u64, transactions: Vec<SignedTransaction>) -> Hash32 {
        let record = self.record();
        let store = self
            .stores
            .store(LANE, &record.incarnation)
            .expect("lane store");
        let instance = self.stores.instance(LANE, &record.incarnation);
        assert_eq!(
            height,
            store.height() + 1,
            "continue the original lane store"
        );
        let config = super::super::lane_height_config(&record).unwrap();
        let parent = store
            .entry(height - 1)
            .expect("read original committed predecessor")
            .map(|entry| (entry.commit_qc.block_hash, entry.commit_qc.result))
            .unwrap_or_else(|| {
                (
                    super::super::lane_genesis_hash(&self.chain.network_id(), &record),
                    super::super::lane_genesis_result(&record),
                )
            });
        let tip = self.chain.height();
        let anchors = Arc::new(GlobalAnchors::new(
            Arc::clone(self.chain.state()),
            Arc::new(AppliedWatch::new(tip, Some(self.anchor(tip)))),
        ));
        let mut executor = LaneExecutor::<_, _, NoTransactions>::begin_recover(
            record.clone(),
            config.clone(),
            instance,
            anchors,
            StatelessChecks::new(self.chain.network_id()),
            None,
            super::super::lane_genesis_hash(&self.chain.network_id(), &record),
            store.clone(),
            Arc::clone(&self.crypto),
            self.chain.state().ivm_execution_budget(),
        )
        .complete()
        .unwrap_or_else(|(_, error)| panic!("original lane recovery: {error}"));
        let payload = LaneBatch {
            anchor_height: anchor,
            anchor_hash: self.anchor(anchor),
            transactions,
        }
        .to_payload();
        let header = BlockHeader {
            instance,
            epoch: config.epoch.id,
            height,
            origin_view: 0,
            parent_hash: parent.0,
            parent_result: parent.1,
            payload_hash: payload_hash(&*self.crypto, &payload),
            availability_digest: Hash32::ZERO,
            payload_len: u32::try_from(payload.len()).expect("small"),
            proposer: 0,
            skipped_leaders: Vec::new(),
            control_witness: iroha_sumeragi::types::ControlWitness::empty(),
            attest: false,
        };
        let budget = self.chain.state().ivm_execution_budget();
        let mut original = iroha_allocation::ChargedBuffer::new(payload.len(), &budget).unwrap();
        original.append(&payload).unwrap();
        let payload = PayloadBytes::from_charged(original, &budget)
            .unwrap_or_else(|_| panic!("original fixture lane payload backing/control"));
        let signer = KeyPairSigner::new(&self.keys[0]).unwrap();
        let authored = PayloadAuthoring::new(header, payload)
            .complete(instance, &config, &budget, &*self.crypto, &signer)
            .unwrap_or_else(|(_, error)| {
                panic!("original lane author signatures/codeword: {error:?}")
            });
        drop(authored.codeword);
        let block = authored.body;
        let block_hash = block.hash(&*self.crypto);
        let outcome = executor.execute(&block, &block_hash);
        let Some(ExecOutcome::Valid(result)) = outcome else {
            panic!("original lane execution must succeed: {outcome:?}");
        };
        let crypto = BlsCrypto::new();
        crypto
            .admit_committee(
                record
                    .committee
                    .iter()
                    .map(|member| (member.peer.public_key(), member.pop.as_slice())),
            )
            .unwrap();
        let votes = self
            .keys
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, key)| {
                assert_eq!(key.public_key(), record.committee[index].peer.public_key());
                let mut vote = Vote {
                    kind: VoteKind::Commit,
                    instance,
                    epoch: block.header().epoch,
                    height,
                    view: block.header().origin_view,
                    block_hash,
                    result,
                    attest: false,
                    signer: u32::try_from(index).unwrap(),
                    sig: Signature([0; SIGNATURE_LEN]),
                    attestation: None,
                };
                vote.sig = KeyPairSigner::new(key).unwrap().sign(&vote.preimage());
                vote
            })
            .collect::<Vec<_>>();
        let qc = form_qc(&crypto, 4, &votes.iter().collect::<Vec<_>>()).unwrap();
        iroha_sumeragi::crypto::Verifier::new(
            &crypto,
            &instance,
            &config.epoch.id,
            &config.committee,
        )
        .verify_qc_signatures(&qc)
        .expect("original exact quorum signatures");
        assert_eq!(executor.prepare(&block, &qc).unwrap(), Some(result));
        store
            .append(&block, &qc)
            .expect("append original prepared lane block");
        executor.commit(&block, &qc).unwrap();
        block_hash
    }

    fn committed(&self, tx: &SignedTransaction) -> bool {
        self.chain
            .state()
            .view()
            .has_entrypoint(tx.hash_as_entrypoint())
    }

    /// A merge-only proposal for the next height carrying `merges` with time floor `floor`.
    fn proposal(&self, merges: &[SumeragiLaneMerge], floor: u64) -> SignedBlock {
        let view = self.chain.state().view();
        let parent = view
            .latest_block()
            .expect("parent history read completes")
            .expect("parent");
        drop(view);
        payload::assemble_with_merges(
            self.chain.state(),
            Assembly {
                parent: &parent,
                view: 0,
                cadence: Duration::from_millis(1),
            },
            &[],
            &MergeProposal {
                merges: merges.to_vec(),
                transactions: 0,
                time_floor_ms: floor,
            },
        )
        .expect("a merge-only proposal")
    }
}

/// Run a borrowed consumer over the original four-validator chain and certified
/// lane store. The producer below still executes, signs, prepares and publishes
/// every requested lane block through the actual native custody path.
pub(crate) fn with_original_lane_merge_fixture(
    test: impl FnOnce(
        &CertifiedTestChain,
        Arc<super::super::registry::LaneStores>,
        &dyn Fn(u64, u64, Vec<SignedTransaction>) -> Hash32,
        [SignedTransaction; 2],
    ) + Send
    + 'static,
) {
    crate::sumeragi::threads::sumeragi_thread_builder("sumeragi-original-lane-merge-test")
        .spawn(move || {
            let mut fixture = Fixture::start();
            let active_from = fixture.record().active_from;
            assert_eq!(
                active_from, 3,
                "the actual signed fixed-lane activation height"
            );
            while fixture.chain.height() < active_from {
                // The real chain helper inserts signed clock work, executes it and
                // commits its exact three-vote certificate; this creates no empty block.
                fixture.chain.commit(Vec::new());
            }
            assert_eq!(fixture.chain.height(), active_from);
            assert!(fixture.record().admits_anchor(fixture.chain.height()));
            let transactions = [
                fixture.log(
                    &lane_user(),
                    "first original lane input",
                    GENESIS_MS + 1_000,
                ),
                fixture.log(&lane_user(), "next original lane input", GENESIS_MS + 1_001),
            ];
            let certify =
                |height, anchor, transactions| fixture.certify(height, anchor, transactions);
            test(
                &fixture.chain,
                Arc::clone(&fixture.stores),
                &certify,
                transactions,
            );
        })
        .expect("spawn original lane fixture")
        .join()
        .expect("original lane fixture");
}

#[path = "merge_tests/paid_quantity_source.rs"]
mod paid_quantity_source;

#[test]
fn global_blocks_merge_fresh_lane_blocks_and_drop_what_they_must_not_execute() {
    let mut fixture = Fixture::start();
    let record = fixture.record();
    assert_eq!(
        record.created_at, 1,
        "genesis creates the policy's fixed lane"
    );
    assert_eq!(record.active_from, 3);
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    assert_eq!(fixture.chain.height(), 3);

    // A valid lane block may carry a transaction routed elsewhere. A duplicate across
    // the global prefix and lane input is dropped during merge; within-lane duplicates
    // are rejected by actual lane admission before they can be certified.
    let routed = fixture.log(&lane_user(), "lane", GENESIS_MS - 10);
    let misrouted = fixture.log(&other_user(), "misrouted", GENESIS_MS - 9);
    let direct_duplicate = fixture.log(&lane_user(), "also in global prefix", GENESIS_MS - 11);
    let tip = fixture.certify(
        1,
        3,
        vec![routed.clone(), misrouted.clone(), direct_duplicate.clone()],
    );
    fixture.chain.commit(vec![direct_duplicate.clone()]);
    let merged = fixture.chain.committed(4);
    assert_eq!(merged.block().merged_entrypoint_count(), 1);
    assert_eq!(
        merged
            .block()
            .external_entrypoints_slice()
            .iter()
            .filter(|input| input.hash() == direct_duplicate.hash_as_entrypoint())
            .count(),
        1,
        "the same genuine lane input already in the global prefix executes exactly once"
    );
    for transaction in [&direct_duplicate, &routed] {
        let input_index = merged
            .block()
            .external_entrypoints_slice()
            .iter()
            .position(|input| input.hash() == transaction.hash_as_entrypoint())
            .expect("the original input is retained exactly once");
        let (_, output) = merged
            .block()
            .network_output_at(u32::try_from(input_index).unwrap())
            .expect("the original input owns a Network output");
        assert!(
            output.result.0.is_ok(),
            "the original input must execute successfully: {:?}",
            output.result
        );
    }
    let routed_hash = TransactionEntrypoint::External(routed.clone()).hash();
    let execution = merged
        .block()
        .execution_context()
        .expect("original executed context");
    let context = execution
        .external
        .iter()
        .find(|context| context.entrypoint_hash == routed_hash)
        .expect("the exact merged source has an execution context");
    assert_eq!(
        context,
        &ExternalExecutionContext::new(routed_hash, record.lane, record.dataspace)
    );
    assert_eq!(
        context.lane_id, LANE,
        "retired Nexus defaults cannot remap a merged lane to zero"
    );
    let plan = iroha_data_model::block::lane_admission::RoutingPlan::single(
        iroha_data_model::block::lane_admission::RoutingDecision::new(
            record.lane,
            record.dataspace,
        ),
    );
    assert_eq!(context.routing_plan_digest, plan.digest());
    assert_eq!(context.routing_plan_legs.len(), 1);
    assert_eq!(
        execution
            .external
            .iter()
            .filter(|row| row.entrypoint_hash == routed_hash)
            .count(),
        1
    );

    assert!(
        fixture.committed(&routed),
        "the routed transaction executes"
    );
    assert!(
        !fixture.committed(&misrouted),
        "a misrouted one has no effect"
    );
    let record = fixture.record();
    assert_eq!(record.merged.height, 1);
    assert_eq!(record.merged.block_hash, tip.0);
    assert_eq!(record.merged_at, 4);

    // Blocks without new lane blocks merge nothing.
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    assert_eq!(fixture.record().merged.height, 1);

    // Lane block 2, anchored at 3, merged at 8 > 3 + A: stale, merged without effect.
    let late = fixture.log(&lane_user(), "late", GENESIS_MS - 8);
    fixture.certify(2, 3, vec![late.clone()]);
    fixture.chain.commit(Vec::new());
    assert_eq!(
        fixture.chain.committed(8).block().merged_entrypoint_count(),
        0
    );
    assert!(
        !fixture.committed(&late),
        "a stale block's transactions do not execute"
    );
    assert_eq!(
        fixture.record().merged.height,
        2,
        "the frontier moves past it"
    );
}

#[test]
fn malformed_merges_are_invalid_and_missing_blocks_pending() {
    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let created = GENESIS_MS - 10;
    let tx = fixture.log(&lane_user(), "lane", created);
    let tip = fixture.certify(1, 3, vec![tx]);
    let record = fixture.record();
    let merge = SumeragiLaneMerge {
        lane: LANE,
        incarnation: record.incarnation,
        from: 1,
        to: 1,
        tip_hash: tip.0,
        tip_result: fixture
            .stores
            .block(LANE, &record.incarnation, 1)
            .expect("original lane storage read")
            .expect("certified lane block is present")
            .result
            .0,
    };
    let expand_with = |merges: &[SumeragiLaneMerge], floor: u64| {
        expand(
            fixture.chain.state(),
            &fixture.proposal(merges, floor),
            &*fixture.stores,
            Duration::ZERO,
        )
    };
    let expand_at = |merges: &[SumeragiLaneMerge]| expand_with(merges, created + 1);
    assert!(expand_at(&[merge]).is_ok());
    // The time floor must be exactly one millisecond after the latest merged transaction.
    assert!(matches!(
        expand_with(&[merge], created + 2),
        Err(MergeError::Invalid(_))
    ));
    // A tip that is not the lane's committed block, a gap, another incarnation, a lane that
    // does not exist: invalid.
    for bad in [
        SumeragiLaneMerge {
            tip_hash: [9; 32],
            ..merge
        },
        SumeragiLaneMerge {
            tip_result: [9; 32],
            ..merge
        },
        SumeragiLaneMerge { from: 2, ..merge },
        SumeragiLaneMerge {
            incarnation: [7; 32],
            ..merge
        },
        SumeragiLaneMerge {
            lane: LaneId::new(5),
            ..merge
        },
    ] {
        assert!(
            matches!(expand_at(&[bad]), Err(MergeError::Invalid(_))),
            "{bad:?} is invalid"
        );
    }
    // Heights the local store has not committed: pending, never a verdict.
    assert!(matches!(
        expand_at(&[SumeragiLaneMerge { to: 2, ..merge }]),
        Err(MergeError::Pending(_))
    ));
    // A leader's proposal merges what the store holds.
    let proposed = propose(
        &fixture.chain.state().view(),
        &*fixture.stores,
        fixture.chain.height() + 1,
    )
    .expect("fixture lane storage available");
    assert_eq!(
        proposed,
        MergeProposal {
            merges: vec![merge],
            transactions: 1,
            time_floor_ms: created + 1,
        }
    );
}

#[test]
fn expansion_consumes_only_the_exact_original_proposal() {
    let fixture = Fixture::start();
    let proposal = fixture.chain.proposal(
        None,
        vec![fixture.log(&other_user(), "original proposal", GENESIS_MS - 1)],
    );
    let expansion = expand(
        fixture.chain.state(),
        &proposal,
        &*fixture.stores,
        Duration::ZERO,
    )
    .unwrap();
    let mut foreign = proposal.clone();
    let mut context = foreign.execution_context().cloned().unwrap_or_default();
    context.version = context.version.wrapping_add(1);
    foreign.set_execution_context(Some(context));
    let foreign_hash = foreign.hash();
    let (returned, reason) = expansion
        .apply(
            foreign,
            fixture.chain.state(),
            fixture.chain.state().state_view_generation(),
        )
        .unwrap_err();
    assert_eq!(
        returned.hash(),
        foreign_hash,
        "refusal preserves the caller's original"
    );
    assert!(matches!(reason, MergeError::Invalid(_)));
    let expansion = expand(
        fixture.chain.state(),
        &proposal,
        &*fixture.stores,
        Duration::ZERO,
    )
    .unwrap();
    let expected = proposal.canonical_proposal_wire_hash().unwrap();
    let (retained, input) = expansion
        .apply(
            proposal,
            fixture.chain.state(),
            fixture.chain.state().state_view_generation(),
        )
        .unwrap();
    assert_eq!(retained.canonical_proposal_wire_hash().unwrap(), expected);
    assert!(input.merges.is_empty());
}

#[test]
fn expansion_refuses_equivalent_foreign_state_and_changed_publication() {
    let mut fixture = Fixture::start();
    let foreign = Fixture::start();
    let state = std::sync::Arc::clone(fixture.chain.state());
    let proposal = fixture.chain.proposal(
        None,
        vec![fixture.log(&other_user(), "original proposal", GENESIS_MS - 1)],
    );
    let expected = proposal.canonical_proposal_wire_hash().unwrap();
    let expansion = expand(&state, &proposal, &*fixture.stores, Duration::ZERO).unwrap();
    assert_eq!(
        state.state_view_generation(),
        foreign.chain.state().state_view_generation()
    );
    let (returned, reason) = expansion
        .apply(
            proposal,
            foreign.chain.state(),
            foreign.chain.state().state_view_generation(),
        )
        .unwrap_err();
    assert!(matches!(reason, MergeError::Pending(_)));
    assert_eq!(returned.canonical_proposal_wire_hash().unwrap(), expected);

    let expansion = expand(&state, &returned, &*fixture.stores, Duration::ZERO).unwrap();
    let captured = state.state_view_generation();
    fixture.chain.commit(Vec::new());
    assert_ne!(state.state_view_generation(), captured);
    let (returned, reason) = expansion.apply(returned, &state, captured).unwrap_err();
    assert!(
        matches!(reason, MergeError::SourceChanged { authenticated_generation, observed_generation }
        if authenticated_generation == captured && observed_generation == state.state_view_generation())
    );
    assert_eq!(returned.canonical_proposal_wire_hash().unwrap(), expected);

    let expansion = expand(&state, &returned, &*fixture.stores, Duration::ZERO).unwrap();
    let (returned, reason) = expansion.apply(returned, &state, captured).unwrap_err();
    assert!(
        matches!(reason, MergeError::SourceChanged { authenticated_generation, observed_generation }
        if authenticated_generation == state.state_view_generation() && observed_generation == captured)
    );
    assert_eq!(returned.canonical_proposal_wire_hash().unwrap(), expected);
}

#[test]
fn merged_rejection_event_retains_the_original_native_proposal_header() {
    use crate::{
        block::{BlockValidationError, ValidBlock},
        sumeragi::{network_topology::Topology, schedule},
    };
    use iroha_data_model::{
        block::error::BlockRejectionReason,
        events::pipeline::{BlockStatus, PipelineEventBox},
        parameter::system::ConsensusMode,
    };

    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let transaction = fixture.log(&lane_user(), "original merged source", GENESIS_MS - 1);
    fixture.certify(1, 3, vec![transaction]);
    let state = fixture.chain.state();
    let view = state.view();
    let height = fixture.chain.height() + 1;
    let scheduled = view.world().consensus_schedule().ready(height).unwrap();
    let cadence = Duration::from_millis(scheduled.params.block_time_ms);
    let parent = fixture.chain.committed(height - 1);
    let merges = propose(&view, &*fixture.stores, height).expect("fixture lane storage available");
    assert_eq!(merges.transactions, 1);
    // The source and certified lane are genuine. Only the proposed global cadence is
    // invalid, so validation must emit a deterministic rejection after expansion.
    let proposal = payload::assemble_with_merges(
        state,
        Assembly {
            parent: parent.block(),
            view: 0,
            cadence: cadence + Duration::from_millis(1),
        },
        &[],
        &merges,
    )
    .unwrap();
    let original_header = proposal.header();
    let bytes = proposal.encode_wire().unwrap();
    let header = BlockHeader {
        instance: fixture.chain.instance(),
        epoch: schedule::core_epoch(&scheduled.epoch).unwrap().id,
        height,
        origin_view: original_header.view_change_index(),
        parent_hash: parent.core_hash(),
        parent_result: parent.result(),
        payload_hash: payload_hash(&*fixture.crypto, &bytes),
        availability_digest: Hash32::ZERO,
        payload_len: u32::try_from(bytes.len()).unwrap(),
        proposer: 0,
        skipped_leaders: Vec::new(),
        attest: height == scheduled.epoch.authorization.last_height,
        control_witness: Default::default(),
    };
    // The negative changes only the global cadence; availability uses the original
    // chain's authenticated schedule, proposer custody and State allocation pool.
    let header = fixture
        .chain
        .author_payload(header, bytes.clone())
        .header()
        .clone();
    let topology = Topology::new(
        fixture
            .chain
            .validators()
            .iter()
            .map(|(peer, _)| peer.clone()),
    );
    drop(view);
    let expansion = expand(state, &proposal, &*fixture.stores, Duration::ZERO).unwrap();
    let generation = state.state_view_generation();
    let mut events = Vec::new();
    let (rejected, error) = ValidBlock::validate_sumeragi_block(
        proposal,
        &topology,
        fixture.chain.genesis_account(),
        cadence,
        ConsensusMode::Permissioned,
        expansion,
        &header,
        &bytes,
        state,
    )
    .unpack(|event| events.push(event))
    .err()
    .expect("wrong original cadence must reject");
    assert!(matches!(
        *error,
        BlockValidationError::NonCanonicalBlockTime { .. }
    ));
    assert_eq!(rejected.merged_entrypoint_count(), 1);
    assert_ne!(
        rejected.header(),
        original_header,
        "expanded roots are a different header"
    );
    let [PipelineEventBox::Block(event)] = events.as_slice() else {
        panic!("exactly one authenticated rejection: {events:?}");
    };
    assert_eq!(event.header, original_header);
    assert_eq!(
        event.status,
        BlockStatus::Rejected(BlockRejectionReason::BlockInTheFuture)
    );
    assert_eq!(state.state_view_generation(), generation);
    assert_eq!(state.view().height(), 3);
}

#[test]
fn leader_proposal_preserves_local_storage_error_instead_of_omitting_lane_work() {
    struct FailedStore;
    impl LaneBlockSource for FailedStore {
        fn tip(
            &self,
            _: LaneId,
            _: &[u8; 32],
        ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<std::io::Error>>
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "exact fixture custody failure",
            )
            .into())
        }
        fn block(
            &self,
            _: LaneId,
            _: &[u8; 32],
            _: u64,
        ) -> Result<
            Option<CommittedLaneBlock>,
            crate::execution_attempt::ExecutionAttemptError<std::io::Error>,
        > {
            panic!("tip failure must stop proposal before reading a block")
        }
        fn wait_for(
            &self,
            _: LaneId,
            _: &[u8; 32],
            _: u64,
            _: Duration,
        ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<std::io::Error>> {
            panic!("proposal does not wait through a storage error")
        }
    }
    let mut fixture = Fixture::start();
    fixture.chain.commit(Vec::new());
    fixture.chain.commit(Vec::new());
    let error = propose(
        &fixture.chain.state().view(),
        &FailedStore,
        fixture.chain.height() + 1,
    )
    .expect_err("a leader must not silently omit lane work after a storage failure");
    assert_eq!(error.io_kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "exact fixture custody failure");
}
