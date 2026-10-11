//! Original LaneExecutor results and real BLS quorum controls for historical lane evidence.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use std::{collections::BTreeSet, io, sync::Arc, time::Duration};

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    account::AccountId,
    block::BlockHeader as GlobalHeader,
    isi::Log,
    sumeragi_lanes::SumeragiLaneMember,
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder, TransactionEntrypoint},
};
use iroha_model_base::{
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use iroha_sumeragi::{
    api::ExecOutcome,
    availability::{AvailabilitySource, AvailableBody, PayloadAuthoring, PayloadBytes},
    crypto::{Crypto as _, Signer as _},
    message::{BlockHeader, Qc, SyncEntry},
    preimage::payload_hash,
    types::{AggregateSignature, Bitmap, ControlWitness, SIGNATURE_LEN},
};

use super::*;
use crate::sumeragi::{
    crypto::KeyPairSigner,
    driver::{
        SharedCrypto,
        traits::{BlockStore, Executor as _},
    },
    durable_artifact::{BodyReadError, BodyReadJob, BodyReader},
    lanes::{
        LaneBatch,
        executor::{AnchorSource, LaneExecutor, LaneTransactions},
    },
};

struct Anchors {
    hash: HashOf<GlobalHeader>,
    available: bool,
}
impl AnchorView for Anchors {
    fn applied_hash(&self, height: u64) -> Option<HashOf<GlobalHeader>> {
        (self.available && height == 3).then_some(self.hash)
    }
    fn creation_time_ms(&self, height: u64) -> Result<Option<u64>, Attempt<io::Error>> {
        Ok(self.applied_hash(height).map(|_| 10_000))
    }
}
impl AnchorSource for Anchors {
    fn wait_for(&self, height: u64, _timeout: Duration) -> bool {
        self.applied_hash(height).is_some()
    }
    fn tip(&self) -> (u64, HashOf<GlobalHeader>) {
        (3, self.hash)
    }
}
struct NoTransactions;
impl LaneTransactions for NoTransactions {
    fn candidates(
        &self,
        _height: u64,
        _max_bytes: usize,
        _skip: &BTreeSet<HashOf<TransactionEntrypoint>>,
    ) -> Result<Vec<SignedTransaction>, crate::execution_attempt::ExecutionDeferred> {
        Ok(Vec::new())
    }
}
struct EmptyStore;
impl BodyReader for EmptyStore {
    fn begin_read(&self, _: AvailabilitySource) -> Result<Box<dyn BodyReadJob>, BodyReadError> {
        panic!("an empty fixture store never reads a committed body")
    }
}
impl BlockStore for EmptyStore {
    fn committed_body(&self, _: u64) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
        Ok(None)
    }
    fn height(&self) -> u64 {
        0
    }
    fn entry(&self, _: u64) -> Result<Option<SyncEntry>, Attempt<io::Error>> {
        Ok(None)
    }
    fn availability_source(
        &self,
        _: u64,
        _: Hash32,
    ) -> Result<Option<AvailabilitySource>, Attempt<io::Error>> {
        Ok(None)
    }
    fn append(&self, _: &AvailableBody, _: &Qc) -> Result<(), Attempt<io::Error>> {
        panic!("the executor fixture must not publish while constructing evidence")
    }
}

struct Fixture {
    record: SumeragiLaneRecord,
    network: NetworkId,
    anchors: Arc<Anchors>,
    prior: SumeragiLaneFrontier,
    body: AvailableBody,
    qc: Qc,
    budget: iroha_allocation::AllocationBudget,
    keys: Vec<KeyPair>,
}
const CHAIN: &str = "native-lane-entry-test";
impl Fixture {
    fn new() -> Self {
        let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"lane verifier network",
        )));
        let anchors = Arc::new(Anchors {
            hash: HashOf::from_untyped_unchecked(Hash::new(b"global anchor at three")),
            available: true,
        });
        let mut keys = (1..=4)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
        let mut record = SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(2),
            dataspace: DataSpaceId::new(0),
            incarnation: [0x73; 32],
            params: Default::default(),
            committee: keys
                .iter()
                .map(|key| SumeragiLaneMember {
                    peer: PeerId::new(key.public_key().clone()),
                    pop: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
                })
                .collect(),
            created_at: 1,
            active_from: 3,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 3,
            rescued: 0,
        };
        let prior = SumeragiLaneFrontier {
            height: 0,
            block_hash: lane_genesis_hash(&network, &record).0,
            result: lane_genesis_result(&record).0,
        };
        record.merged = prior;
        let user = KeyPair::from_seed(vec![8; 32], Algorithm::Ed25519);
        let mut tx = TransactionBuilder::new(
            network,
            AccountId::new(user.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            iroha_data_model::Level::INFO,
            "lane verifier execution".to_owned(),
        )]);
        tx.set_creation_time(Duration::from_millis(9_000));
        let batch = LaneBatch {
            anchor_height: 3,
            anchor_hash: anchors.hash,
            transactions: vec![tx.sign(user.private_key())],
        };
        let config = lane_height_config(&record).unwrap();
        let crypto = Arc::new(BlsCrypto::new());
        crypto
            .admit_committee(
                record
                    .committee
                    .iter()
                    .map(|member| (member.peer.public_key(), member.pop.as_slice())),
            )
            .unwrap();
        let budget = iroha_allocation::AllocationBudget::new(1 << 25);
        let payload = batch.to_payload();
        let header = BlockHeader {
            control_witness: ControlWitness::empty(),
            instance: lane_instance(&*crypto, &network, CHAIN, &record),
            epoch: config.epoch.id,
            height: 1,
            origin_view: 0,
            parent_hash: Hash32(prior.block_hash),
            parent_result: Hash32(prior.result),
            payload_hash: payload_hash(&*crypto, &payload),
            availability_digest: Hash32::ZERO,
            payload_len: u32::try_from(payload.len()).unwrap(),
            proposer: 0,
            skipped_leaders: Vec::new(),
        };
        let mut charged = iroha_allocation::ChargedBuffer::new(payload.len(), &budget).unwrap();
        charged.append(&payload).unwrap();
        let payload = PayloadBytes::from_charged(charged, &budget)
            .unwrap_or_else(|_| panic!("original fixture payload"));
        let authored = PayloadAuthoring::new(header, payload)
            .complete(
                lane_instance(&*crypto, &network, CHAIN, &record),
                &config,
                &budget,
                &*crypto,
                &KeyPairSigner::new(&keys[0]).unwrap(),
            )
            .unwrap_or_else(|(_, error)| panic!("original signed lane availability: {error:?}"));
        drop(authored.codeword);
        let block = authored.body;
        let shared: SharedCrypto = crypto.clone();
        let mut executor = LaneExecutor::<_, _, NoTransactions>::begin_recover(
            record.clone(),
            config,
            lane_instance(&*crypto, &network, CHAIN, &record),
            Arc::clone(&anchors),
            StatelessChecks::new(network),
            None,
            Hash32(prior.block_hash),
            Arc::new(EmptyStore),
            shared,
            budget.clone(),
        )
        .complete()
        .unwrap_or_else(|(_, error)| panic!("empty original lane recovery: {error}"));
        let Some(ExecOutcome::Valid(result)) = executor.execute(&block, &block.hash(&*crypto))
        else {
            panic!("original lane execution must be valid");
        };
        let commit_qc = Qc {
            kind: VoteKind::Commit,
            instance: block.header().instance,
            epoch: block.header().epoch,
            height: 1,
            view: 0,
            block_hash: block.hash(&*crypto),
            result,
            signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
            agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
        };
        let mut fixture = Self {
            record,
            network,
            anchors,
            prior,
            body: block,
            qc: commit_qc,
            budget,
            keys,
        };
        fixture.resign(3);
        fixture
    }
    fn resign(&mut self, count: usize) {
        self.qc.signers = Bitmap::from_indices(4, (0..count).map(|index| index as u32)).unwrap();
        let preimage = self.qc.preimage();
        let signatures = self.keys[..count]
            .iter()
            .map(|key| KeyPairSigner::new(key).unwrap().sign(&preimage))
            .collect::<Vec<_>>();
        self.qc.agg_sig = BlsCrypto::new().aggregate(&signatures);
    }
    fn replace_payload(&mut self, bytes: &[u8], config: &HeightConfig) {
        let crypto = BlsCrypto::new();
        let mut header = self.body.header().clone();
        header.payload_len = u32::try_from(bytes.len()).unwrap();
        header.payload_hash = payload_hash(&crypto, bytes);
        let mut charged = iroha_allocation::ChargedBuffer::new(bytes.len(), &self.budget).unwrap();
        charged.append(bytes).unwrap();
        let payload = PayloadBytes::from_charged(charged, &self.budget)
            .unwrap_or_else(|_| panic!("original replacement fixture payload"));
        let authored = PayloadAuthoring::new(header, payload)
            .complete(
                self.body.source().instance(),
                config,
                &self.budget,
                &crypto,
                &KeyPairSigner::new(&self.keys[0]).unwrap(),
            )
            .unwrap_or_else(|(_, error)| panic!("original reauthored fixture: {error:?}"));
        drop(authored.codeword);
        self.body = authored.body;
        self.qc.block_hash = self.body.hash(&crypto);
        self.resign(3);
    }
    fn verify(&self) -> Result<LaneResult, LaneEntryError> {
        verify_lane_entry(
            &self.record,
            &self.network,
            CHAIN,
            &*self.anchors,
            &LaneChainView::default(),
            &self.prior,
            &self.body,
            &self.qc,
        )
    }
}

#[test]
fn original_execution_and_exact_real_quorum_reproduce_lane_result() {
    let fixture = Fixture::new();
    let result = fixture.verify().unwrap();
    assert_eq!(result.hash(), fixture.qc.result);
    assert_eq!(result.anchor_hash, fixture.anchors.hash);
    assert_eq!(result.tx_hashes.len(), 1);
}

#[test]
fn source_context_predecessor_pop_and_exact_quorum_are_all_required() {
    for mutation in 0..10 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => fixture.record.incarnation[0] ^= 1,
            1 => fixture.record.committee[0].pop[0] ^= 1,
            2 => fixture.prior.result[0] ^= 1,
            3 => fixture.qc.agg_sig.0[0] ^= 1,
            4 => fixture.resign(2),
            5 => fixture.resign(4),
            6 => {
                fixture.qc.result.0[0] ^= 1;
                fixture.resign(3);
            }
            7 => fixture.record.committee.swap(0, 1),
            8 => {
                fixture.network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"other network"),
                ))
            }
            9 => fixture.prior.height = u64::MAX,
            _ => unreachable!(),
        }
        assert!(fixture.verify().is_err(), "mutation {mutation}");
    }
    let fixture = Fixture::new();
    assert!(
        verify_lane_certificate(
            &fixture.record,
            &fixture.network,
            "other-chain",
            &fixture.prior,
            &fixture.body,
            &fixture.qc
        )
        .is_err()
    );
}

#[test]
fn anchor_history_refusal_retains_exact_source_through_lane_evidence_retry() {
    struct FundedAnchor<'a> {
        original: &'a Anchors,
        budget: iroha_allocation::AllocationBudget,
    }
    impl AnchorView for FundedAnchor<'_> {
        fn applied_hash(&self, height: u64) -> Option<HashOf<GlobalHeader>> {
            self.original.applied_hash(height)
        }
        fn creation_time_ms(&self, height: u64) -> Result<Option<u64>, Attempt<io::Error>> {
            let _read = self
                .budget
                .try_reserve(std::alloc::Layout::new::<u64>())
                .map_err(|original| Attempt::Deferred(original.into()))?;
            self.original.creation_time_ms(height)
        }
    }
    let fixture = Fixture::new();
    let anchors = FundedAnchor {
        original: &fixture.anchors,
        budget: iroha_allocation::AllocationBudget::new(std::mem::size_of::<u64>()),
    };
    let layout = std::alloc::Layout::new::<u64>();
    let occupied = anchors.budget.try_reserve(layout).unwrap();
    let expected = crate::execution_attempt::ExecutionDeferred::from(
        anchors.budget.try_reserve(layout).unwrap_err(),
    );
    let verify = || {
        verify_lane_entry(
            &fixture.record,
            &fixture.network,
            CHAIN,
            &anchors,
            &LaneChainView::default(),
            &fixture.prior,
            &fixture.body,
            &fixture.qc,
        )
    };
    let pointer = fixture.body.payload().as_slice().as_ptr();
    for _ in 0..2 {
        assert!(
            matches!(verify(), Err(LaneEntryError::AnchorDeferred(reason)) if reason == expected)
        );
        assert_eq!(fixture.body.payload().as_slice().as_ptr(), pointer);
    }
    drop(occupied);
    assert_eq!(verify().unwrap().hash(), fixture.qc.result);
}

#[test]
fn unavailable_anchor_is_distinct_from_bad_admission_or_bad_certificate() {
    let fixture = Fixture::new();
    let missing = Anchors {
        hash: fixture.anchors.hash,
        available: false,
    };
    assert!(matches!(
        verify_lane_entry(
            &fixture.record,
            &fixture.network,
            CHAIN,
            &missing,
            &LaneChainView::default(),
            &fixture.prior,
            &fixture.body,
            &fixture.qc
        ),
        Err(LaneEntryError::UnavailableAnchor)
    ));
    let result = fixture.verify().unwrap();
    let history = LaneChainView {
        previous_anchor: result.anchor_height,
        recent: result
            .tx_hashes
            .iter()
            .map(|hash| (*hash, result.anchor_height))
            .collect(),
    };
    assert!(matches!(
        verify_lane_entry(
            &fixture.record,
            &fixture.network,
            CHAIN,
            &*fixture.anchors,
            &history,
            &fixture.prior,
            &fixture.body,
            &fixture.qc
        ),
        Err(LaneEntryError::Admission(AdmissionError::Duplicate(0)))
    ));
}

#[test]
fn valid_certificate_does_not_assert_its_payload_is_an_admissible_batch() {
    let mut fixture = Fixture::new();
    let config = lane_height_config(&fixture.record).unwrap();
    fixture.replace_payload(&[0xff], &config);
    assert!(
        verify_lane_certificate(
            &fixture.record,
            &fixture.network,
            CHAIN,
            &fixture.prior,
            &fixture.body,
            &fixture.qc
        )
        .is_ok()
    );
    assert!(matches!(
        fixture.verify(),
        Err(LaneEntryError::Admission(AdmissionError::Encoding(_)))
    ));
}

#[test]
fn equal_epoch_and_header_do_not_relabel_a_body_checked_under_foreign_parameters() {
    let mut fixture = Fixture::new();
    let original = fixture.body.header().clone();
    let payload = fixture.body.payload().as_slice().to_vec();
    let mut foreign = lane_height_config(&fixture.record).unwrap();
    foreign.params.max_block_bytes -= 1;
    fixture.replace_payload(&payload, &foreign);
    assert_eq!(fixture.body.header(), &original);
    assert!(matches!(
        fixture.verify(),
        Err(LaneEntryError::Binding(
            "body was authenticated under another historical authority"
        ))
    ));
}

fn certified_successor(fixture: &mut Fixture, parent: SumeragiLaneFrontier) {
    let crypto = BlsCrypto::new();
    let config = lane_height_config(&fixture.record).unwrap();
    let mut header = fixture.body.header().clone();
    header.height = parent.height + 1;
    header.parent_hash = Hash32(parent.block_hash);
    header.parent_result = Hash32(parent.result);
    let authored = PayloadAuthoring::new(header, fixture.body.payload().clone())
        .complete(
            fixture.body.source().instance(),
            &config,
            &fixture.budget,
            &crypto,
            &KeyPairSigner::new(&fixture.keys[0]).unwrap(),
        )
        .unwrap_or_else(|(_, error)| panic!("original signed successor: {error:?}"));
    drop(authored.codeword);
    fixture.body = authored.body;
    fixture.qc.height = fixture.body.header().height;
    fixture.qc.block_hash = fixture.body.hash(&crypto);
    fixture.qc.result = crypto.hash(&fixture.qc.height.to_be_bytes());
    fixture.resign(3);
}

fn ancestry(
    fixture: &Fixture,
    subject: u64,
    window: u64,
) -> Result<LaneAncestry, LaneAncestryError> {
    LaneAncestry::new(
        fixture.body.source().instance(),
        lane_height_config(&fixture.record).unwrap(),
        fixture.prior,
        SumeragiLaneFrontier {
            height: fixture.qc.height,
            block_hash: fixture.qc.block_hash.0,
            result: fixture.qc.result.0,
        },
        subject,
        window,
    )
    .map_err(|(_, error)| error)
}

fn admitted_crypto(fixture: &Fixture) -> BlsCrypto {
    let crypto = BlsCrypto::new();
    crypto
        .admit_committee(
            fixture
                .record
                .committee
                .iter()
                .map(|member| (member.peer.public_key(), member.pop.as_slice())),
        )
        .unwrap();
    crypto
}

#[test]
fn anchored_lane_ancestry_walks_every_source_above_the_complete_native_interval() {
    let mut fixture = Fixture::new();
    let mut frames = vec![(fixture.body.clone(), fixture.qc.clone())];
    for _ in 0..2 {
        let parent = SumeragiLaneFrontier {
            height: fixture.qc.height,
            block_hash: fixture.qc.block_hash.0,
            result: fixture.qc.result.0,
        };
        certified_successor(&mut fixture, parent);
        frames.push((fixture.body.clone(), fixture.qc.clone()));
    }
    let mut cursor = ancestry(&fixture, 3, 10).unwrap();
    assert_eq!(
        cursor.next_frontier().unwrap().height,
        cursor.next_height().unwrap()
    );
    assert!(std::ptr::eq(cursor.configuration_owner(), cursor.config()));
    assert_eq!(cursor.parent_height(), 2);
    assert_eq!(cursor.demotion_interval(), Some((1, 1)));
    assert_eq!(cursor.config(), fixture.body.source().config());
    let crypto = admitted_crypto(&fixture);
    let held = fixture.budget.reserved_bytes();
    // A correct interval cannot skip the original anchor's higher frame.
    assert_eq!(
        cursor.advance(&crypto, &frames[1].0, &frames[1].1),
        Err(LaneAncestryError::Branch)
    );
    assert_eq!(cursor.next_height(), Some(3));
    let mut forged = frames[2].1.clone();
    forged.agg_sig.0[0] ^= 1;
    assert_eq!(
        cursor.advance(&crypto, &frames[2].0, &forged),
        Err(LaneAncestryError::Certificate)
    );
    assert_eq!(cursor.next_height(), Some(3));
    for (body, qc) in frames.iter().rev() {
        assert_eq!(cursor.next_height(), Some(qc.height));
        cursor.advance(&crypto, body, qc).unwrap();
    }
    assert_eq!(cursor.next_height(), None);
    assert_eq!(
        cursor.advance(&crypto, &frames[0].0, &frames[0].1),
        Err(LaneAncestryError::Complete)
    );
    assert_eq!(
        fixture.budget.reserved_bytes(),
        held,
        "cursor never clones or funds a second source"
    );
}

#[test]
fn anchored_lane_ancestry_rejects_a_validly_certified_replacement_branch_and_result() {
    let mut fixture = Fixture::new();
    let original = (fixture.body.clone(), fixture.qc.clone());
    let crypto = admitted_crypto(&fixture);
    let mut cursor = ancestry(&fixture, 2, 10).unwrap();
    let config = lane_height_config(&fixture.record).unwrap();
    fixture.replace_payload(&[0xff], &config);
    // A quorum can certify this replacement; the global branch still cannot change.
    assert!(
        verify_lane_certificate(
            &fixture.record,
            &fixture.network,
            CHAIN,
            &fixture.prior,
            &fixture.body,
            &fixture.qc
        )
        .is_ok()
    );
    assert_eq!(
        cursor.advance(&crypto, &fixture.body, &fixture.qc),
        Err(LaneAncestryError::Branch)
    );
    assert_eq!(cursor.next_height(), Some(1));
    fixture.body = original.0;
    fixture.qc = original.1;
    let original_result = fixture.qc.result;
    fixture.qc.result.0[0] ^= 1;
    fixture.resign(3);
    assert!(
        verify_lane_certificate(
            &fixture.record,
            &fixture.network,
            CHAIN,
            &fixture.prior,
            &fixture.body,
            &fixture.qc
        )
        .is_ok()
    );
    assert_eq!(
        cursor.advance(&crypto, &fixture.body, &fixture.qc),
        Err(LaneAncestryError::Branch)
    );
    fixture.qc.result = original_result;
    fixture.resign(3);
    cursor.advance(&crypto, &fixture.body, &fixture.qc).unwrap();
    assert_eq!(cursor.next_height(), None);
}

#[test]
fn anchored_lane_ancestry_distinguishes_native_coverage_and_independent_genesis() {
    let fixture = Fixture::new();
    assert!(matches!(
        ancestry(&fixture, 0, 10),
        Err(LaneAncestryError::Uncovered)
    ));
    assert!(matches!(
        ancestry(&fixture, 3, 10),
        Err(LaneAncestryError::Uncovered)
    ));
    assert!(ancestry(&fixture, 2, 10).is_ok());
    let genesis = ancestry(&fixture, 1, 10).unwrap();
    assert_eq!(genesis.parent_height(), 0);
    assert_eq!(genesis.demotion_interval(), None);
    assert_eq!(genesis.next_height(), None);
    let mut wrong = fixture.prior;
    wrong.block_hash[0] ^= 1;
    assert!(matches!(
        LaneAncestry::new(
            fixture.body.source().instance(),
            lane_height_config(&fixture.record).unwrap(),
            fixture.prior,
            wrong,
            1,
            10
        ),
        Err((_, LaneAncestryError::Authority))
    ));
    let mut config = lane_height_config(&fixture.record).unwrap();
    config.epoch.authority_generation.0[0] ^= 1;
    assert!(matches!(
        LaneAncestry::new(
            fixture.body.source().instance(),
            config,
            fixture.prior,
            fixture.prior,
            1,
            10
        ),
        Err((_, LaneAncestryError::Authority))
    ));
}

#[test]
fn anchored_lane_ancestry_rejects_broken_parent_links_and_relabelled_source_policy() {
    let mut fixture = Fixture::new();
    let crypto = admitted_crypto(&fixture);
    let mut wrong_genesis = fixture.prior;
    wrong_genesis.result[0] ^= 1;
    certified_successor(&mut fixture, wrong_genesis);
    let mut cursor = ancestry(&fixture, 2, 10).unwrap();
    assert_eq!(
        cursor.advance(&crypto, &fixture.body, &fixture.qc),
        Err(LaneAncestryError::Branch)
    );
    assert_eq!(cursor.next_height(), Some(1));

    let mut fixture = Fixture::new();
    let mut cursor = ancestry(&fixture, 2, 10).unwrap();
    let original = fixture.body.header().clone();
    let bytes = fixture.body.payload().as_slice().to_vec();
    let mut foreign = lane_height_config(&fixture.record).unwrap();
    foreign.params.max_block_bytes -= 1;
    fixture.replace_payload(&bytes, &foreign);
    assert_eq!(fixture.body.header(), &original);
    assert_eq!(
        cursor.advance(&crypto, &fixture.body, &fixture.qc),
        Err(LaneAncestryError::Branch)
    );
    assert_eq!(cursor.next_height(), Some(1));
}
