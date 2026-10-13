//! Native signed four-validator lane decode/retry component controls.
//!
//! These authenticate lane storage and execution ownership; they do not replace
//! signed global genesis, fee settlement or whole-network qualification.

use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::{
    availability_schedule::AvailabilitySchedule,
    crypto::{BlsCrypto, KeyPairSigner},
    lanes::{
        lane_genesis_hash, lane_genesis_result, lane_height_config, lane_instance,
        store::FileLaneBlockStore,
    },
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    Level, NetworkId,
    account::AccountId,
    isi::Log,
    parameter::system::SumeragiParameters,
    sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember},
    transaction::{FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_model_base::{
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use iroha_sumeragi::{
    availability::{AvailabilitySource, PayloadAuthoring},
    crypto::Signer,
    message::{BlockHeader as NativeHeader, VoteKind},
    types::Bitmap,
};

struct Anchor(HashOf<BlockHeader>, AllocationBudget);
impl AnchorView for Anchor {
    fn applied_hash(&self, height: u64) -> Option<HashOf<BlockHeader>> {
        (height == 7).then_some(self.0)
    }
    fn creation_time_ms(&self, height: u64) -> Result<Option<u64>, Attempt<io::Error>> {
        let _read = self
            .1
            .try_reserve(std::alloc::Layout::new::<u64>())
            .map_err(|original| Attempt::Deferred(original.into()))?;
        Ok((height == 7).then_some(5_000))
    }
}
impl AnchorSource for Anchor {
    fn wait_for(&self, height: u64, _: Duration) -> bool {
        height == 7
    }
    fn tip(&self) -> (u64, HashOf<BlockHeader>) {
        (7, self.0)
    }
}
struct IntrinsicComponentCheck;
impl TransactionCheck for IntrinsicComponentCheck {
    fn check(&self, _: &TransactionEntrypoint, _: u64) -> Result<(), String> {
        Ok(())
    }
}
struct NoRows;
impl LaneTransactions for NoRows {
    type Lease = ();

    fn candidates(
        &self,
        _: u64,
        _: usize,
        _: &BTreeSet<HashOf<TransactionEntrypoint>>,
        _: &iroha_allocation::AllocationBudget,
    ) -> Result<
        (Vec<TransactionEntrypoint>, Self::Lease),
        crate::sumeragi::lanes::executor::LaneSelectionError,
    > {
        Ok((Vec::new(), ()))
    }

    fn retain_prefix(&self, _: &mut Self::Lease, _: usize) {}
    fn lease_is_current(
        &self,
        _: &Self::Lease,
        _: &iroha_allocation::AllocationBudget,
    ) -> Result<bool, crate::sumeragi::driver::traits::PublicationError> {
        Ok(true)
    }
}
struct Schedule(AvailabilitySource);
impl AvailabilitySchedule for Schedule {
    fn instance(&self) -> Hash32 {
        self.0.instance()
    }
    fn height_config(&self, _: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        Ok(Some(self.0.config().clone()))
    }
}
type Lane = LaneExecutor<Anchor, IntrinsicComponentCheck, NoRows>;
struct Fixture {
    _directory: tempfile::TempDir,
    record: SumeragiLaneRecord,
    anchor: Arc<Anchor>,
    body: AvailableBody,
    qc: Qc,
    store: Arc<FileLaneBlockStore>,
    crypto: SharedCrypto,
    budget: AllocationBudget,
    genesis: Hash32,
    transaction: SignedTransaction,
}
impl Fixture {
    fn new(canonical: bool) -> Self {
        Self::with_creation(canonical, 6_000)
    }

    fn with_creation(canonical: bool, created_ms: u64) -> Self {
        let mut keys: Vec<_> = (1..=4)
            .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect();
        keys.sort_by(|left, right| left.public_key().cmp(right.public_key()));
        let signers: Vec<_> = keys
            .iter()
            .map(|key| KeyPairSigner::new(key).unwrap())
            .collect();
        let record = SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(16),
            dataspace: DataSpaceId::new(0),
            incarnation: [0x29; 32],
            params: SumeragiParameters::default(),
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
        let concrete = BlsCrypto::new();
        concrete
            .admit_committee(
                record
                    .committee
                    .iter()
                    .map(|member| (member.peer.public_key(), member.pop.as_slice())),
            )
            .unwrap();
        let crypto: SharedCrypto = Arc::new(concrete);
        let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"HC29 component global root",
        )));
        let instance = lane_instance(&*crypto, &network, "HC29 component", &record);
        let genesis = lane_genesis_hash(&network, &record);
        let config = lane_height_config(&record).unwrap();
        let anchor = Arc::new(Anchor(
            network.into_genesis_hash(),
            AllocationBudget::new(std::mem::size_of::<u64>()),
        ));
        let key = KeyPair::from_seed(vec![0x29; 32], Algorithm::Ed25519);
        let mut builder = TransactionBuilder::new(
            network,
            AccountId::new(key.public_key().clone()),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Log::new(
            Level::INFO,
            "original signed lane transaction".into(),
        )]);
        builder.set_creation_time(Duration::from_millis(created_ms));
        let transaction = builder.sign(key.private_key());
        let bytes = if canonical {
            LaneBatch {
                anchor_height: 7,
                anchor_hash: anchor.0,
                transactions: vec![TransactionEntrypoint::External(transaction.clone())],
            }
            .to_payload()
        } else {
            vec![0xFF]
        };
        let result = if canonical {
            let Admission::Valid(result) = admit(
                &record,
                &*anchor,
                &LaneChainView::default(),
                &IntrinsicComponentCheck,
                &config,
                &bytes,
            )
            .unwrap() else {
                panic!("applied anchor")
            };
            result.hash()
        } else {
            Hash32::ZERO
        };
        let budget = AllocationBudget::new(1 << 25);
        let mut payload = PayloadBytes::from_untrusted(bytes).unwrap();
        payload.admit(&budget).unwrap();
        let header = NativeHeader {
            instance,
            epoch: config.epoch.id,
            height: 1,
            origin_view: 0,
            parent_hash: genesis,
            parent_result: lane_genesis_result(&record),
            payload_hash: iroha_sumeragi::preimage::payload_hash(&*crypto, payload.as_slice()),
            availability_digest: Hash32::ZERO,
            payload_len: u32::try_from(payload.as_slice().len()).unwrap(),
            proposer: 0,
            skipped_leaders: Vec::new(),
            control_witness: iroha_sumeragi::types::ControlWitness::default(),
        };
        let authored = PayloadAuthoring::new(header, payload)
            .complete(instance, &config, &budget, &*crypto, &signers[0])
            .unwrap_or_else(|(_, error)| panic!("original signed RS16 availability: {error:?}"));
        drop(authored.codeword);
        let body = authored.body;
        let mut qc = Qc {
            kind: VoteKind::Commit,
            instance,
            epoch: config.epoch.id,
            height: 1,
            view: 0,
            block_hash: body.hash(&*crypto),
            result,
            signers: Bitmap::from_indices(4, [0, 1, 2]).unwrap(),
            agg_sig: iroha_sumeragi::types::AggregateSignature(
                [0; iroha_sumeragi::types::SIGNATURE_LEN],
            ),
        };
        qc.agg_sig = crypto
            .aggregate(
                &signers[..3]
                    .iter()
                    .map(|signer| signer.sign(&qc.preimage()).unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = FileLaneBlockStore::begin_open(
            directory.path(),
            &instance,
            crypto.clone(),
            budget.clone(),
            Arc::new(Schedule(body.source().clone())),
        )
        .unwrap()
        .complete()
        .unwrap_or_else(|(_, error)| panic!("empty native lane store: {error}"));
        Self {
            _directory: directory,
            record,
            anchor,
            body,
            qc,
            store: Arc::new(store),
            crypto,
            budget,
            genesis,
            transaction,
        }
    }
    fn recovery(&self) -> LaneRecovery<Anchor, IntrinsicComponentCheck, NoRows> {
        self.recovery_with_clock(iroha_primitives::time::TimeSource::new_system())
    }

    fn recovery_with_clock(
        &self,
        time_source: iroha_primitives::time::TimeSource,
    ) -> LaneRecovery<Anchor, IntrinsicComponentCheck, NoRows> {
        LaneExecutor::begin_recover(
            self.record.clone(),
            self.body.source().config().clone(),
            self.body.source().instance(),
            self.anchor.clone(),
            IntrinsicComponentCheck,
            None,
            self.genesis,
            self.store.clone(),
            self.crypto.clone(),
            self.budget.clone(),
            time_source,
        )
    }
}
fn allocation_scope<T>(run: impl FnOnce() -> T) -> T {
    // Match the actual standard-library reservation made by Norito's vector decoder.
    let mut destination = Vec::<TransactionEntrypoint>::new();
    destination.try_reserve(1).unwrap();
    let layout =
        std::alloc::Layout::array::<TransactionEntrypoint>(destination.capacity()).unwrap();
    drop(destination);
    let (result, refused) = crate::test_allocations::refuse_one_layout_during(layout, run);
    assert!(
        refused,
        "original transaction-vector destination is refused exactly once"
    );
    result
}
#[test]
fn signed_four_validator_lane_execution_refusal_never_caches_invalid_or_publishes() {
    let fixture = Fixture::new(true);
    let mut lane: Lane = fixture
        .recovery()
        .complete()
        .unwrap_or_else(|_| panic!("empty recovered lane"));
    let hash = fixture.qc.block_hash;
    let pointer = fixture.body.payload().as_slice().as_ptr();
    let retained = fixture.budget.reserved_bytes();
    for _ in 0..2 {
        let original = allocation_scope(|| lane.execute(&fixture.body, &hash, false)).unwrap_err();
        assert!(matches!(&original, PublicationError::Deferred(local)
            if local.execution().and_then(|owner| owner.decode_refusal()).is_some()));
        assert!(
            matches!(allocation_scope(||lane.prepare(&fixture.body,&fixture.qc)),
            Err(PublicationError::Deferred(ref original))
                if original.execution().and_then(|owner| owner.decode_refusal()).is_some())
        );
        assert!(lane.cache.is_empty());
        assert_eq!(lane.applied.height, 0);
        assert_eq!(fixture.body.payload().as_slice().as_ptr(), pointer);
        assert_eq!(fixture.budget.reserved_bytes(), retained);
    }
    assert!(
        matches!(lane.execute(&fixture.body, &hash, false), Ok(Some(ExecOutcome::Valid { result, .. })) if result == fixture.qc.result)
    );
    assert_eq!(
        lane.prepare(&fixture.body, &fixture.qc).unwrap(),
        Some(fixture.qc.result)
    );
    lane.commit(&fixture.body, &fixture.qc).unwrap();
    assert_eq!(lane.applied.height, 1);
    let malformed = Fixture::new(false);
    let mut lane: Lane = malformed
        .recovery()
        .complete()
        .unwrap_or_else(|_| panic!("empty lane"));
    assert_eq!(
        lane.execute(&malformed.body, &malformed.qc.block_hash, false)
            .unwrap(),
        Some(ExecOutcome::Invalid)
    );
    assert_eq!(lane.prepare(&malformed.body, &malformed.qc).unwrap(), None);
    assert!(lane.cache.is_empty());
}
#[test]
fn anchor_read_refusal_retains_original_lane_body_until_capacity_returns() {
    use crate::execution_attempt::ExecutionDeferred;
    use iroha_allocation::AllocationRefusal;
    use std::task::{Context, Waker};

    let fixture = Fixture::new(true);
    let mut lane: Lane = fixture
        .recovery()
        .complete()
        .unwrap_or_else(|_| panic!("empty recovered lane"));
    let layout = std::alloc::Layout::new::<u64>();
    fixture.anchor.1.set_limit_bytes(
        layout.size() + iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
    );
    let mut registration = crate::unit_test_support::release_registration(&fixture.anchor.1);
    let occupied = fixture.anchor.1.try_reserve(layout).unwrap();
    let refusal = fixture.anchor.1.try_reserve(layout).unwrap_err();
    let AllocationRefusal::Capacity { release, .. } = &refusal else {
        panic!("occupied original anchor pool must be a temporary capacity refusal");
    };
    let released = release.clone();
    let mut context = Context::from_waker(Waker::noop());
    assert!(registration.poll_wait(&released, &mut context).is_pending());
    let expected = ExecutionDeferred::from(refusal);
    let pointer = fixture.body.payload().as_slice().as_ptr();
    let retained = fixture.budget.reserved_bytes();
    for _ in 0..2 {
        let execute = lane
            .execute(&fixture.body, &fixture.qc.block_hash, false)
            .unwrap_err();
        let PublicationError::Deferred(original) = execute else {
            panic!("typed original anchor refusal")
        };
        assert_eq!(original.allocation_refusal(), expected.allocation_refusal());
        let prepare = lane.prepare(&fixture.body, &fixture.qc).unwrap_err();
        let PublicationError::Deferred(original) = prepare else {
            panic!("typed original preparation refusal")
        };
        assert_eq!(original.allocation_refusal(), expected.allocation_refusal());
        assert!(lane.cache.is_empty());
        assert_eq!(lane.applied.height, 0);
        assert_eq!(fixture.body.payload().as_slice().as_ptr(), pointer);
        assert_eq!(fixture.budget.reserved_bytes(), retained);
    }
    let unrelated = AllocationBudget::new(layout.size());
    drop(unrelated.try_reserve(layout).unwrap());
    assert!(registration.poll_wait(&released, &mut context).is_pending());
    drop(occupied);
    assert!(registration.poll_wait(&released, &mut context).is_ready());
    assert!(
        matches!(lane.execute(&fixture.body, &fixture.qc.block_hash, false), Ok(Some(ExecOutcome::Valid { result, .. })) if result == fixture.qc.result)
    );
    assert_eq!(
        lane.prepare(&fixture.body, &fixture.qc).unwrap(),
        Some(fixture.qc.result)
    );
    lane.commit(&fixture.body, &fixture.qc).unwrap();
    assert_eq!(lane.applied.height, 1);
    assert_eq!(lane.applied.state.anchor, 7);
}

#[test]
fn signed_four_validator_lane_recovery_keeps_available_phase_and_exact_original_owners() {
    let fixture = Fixture::new(true);
    fixture.store.append(&fixture.body, &fixture.qc).unwrap();
    let recovery = fixture.recovery();
    let (mut recovery, error) = allocation_scope(|| recovery.complete()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(error.get_ref().is_none());
    let (payload, signers) = match recovery.pending.as_ref() {
        Some(RecoveryRead::Decoding(qc, body)) => {
            assert_eq!(body.source(), fixture.body.source());
            assert!(body.admitted_to(&fixture.budget));
            (
                body.payload().as_slice().as_ptr(),
                qc.signers.as_bytes().as_ptr(),
            )
        }
        _ => panic!("completed original acquisition remains available through refused decode"),
    };
    let retained = fixture.budget.reserved_bytes();
    for _ in 0..2 {
        let (original, error) = allocation_scope(|| recovery.complete()).unwrap_err();
        recovery = original;
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error.get_ref().is_none());
        let Some(RecoveryRead::Decoding(qc, body)) = recovery.pending.as_ref() else {
            panic!("original phase")
        };
        assert_eq!(body.payload().as_slice().as_ptr(), payload);
        assert_eq!(qc.signers.as_bytes().as_ptr(), signers);
        assert_eq!(recovery.next, 1);
        assert_eq!(recovery.executor.applied.state, ChainState::default());
        assert_eq!(fixture.budget.reserved_bytes(), retained);
    }
    let lane: Lane = recovery
        .complete()
        .unwrap_or_else(|_| panic!("same-source retry"));
    assert_eq!(lane.applied.height, 1);
    assert_eq!(lane.applied.block_hash, fixture.qc.block_hash);
    assert_eq!(lane.applied.state.anchor, 7);
    assert!(
        lane.applied
            .state
            .view()
            .recent
            .contains_key(&fixture.transaction.hash_as_entrypoint())
    );
    let malformed = Fixture::new(false);
    malformed
        .store
        .append(&malformed.body, &malformed.qc)
        .unwrap();
    let (_, error) = malformed.recovery().complete().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn signed_lane_clock_retains_original_admission_until_exact_boundary_and_certified_replay() {
    for created_ms in [4_000, 6_000] {
        let fixture = Fixture::with_creation(true, created_ms);
        let effective = Duration::from_millis(5_000.max(created_ms + 1));
        let boundary = effective
            .checked_sub(fixture.record.params.max_clock_drift())
            .expect("fixture effective time exceeds the signed drift allowance");
        let (clock, time) = iroha_primitives::time::TimeSource::new_mock(
            boundary
                .checked_sub(Duration::from_millis(1))
                .expect("fixture time has the original one-millisecond predecessor"),
        );
        let mut lane = fixture
            .recovery_with_clock(time.clone())
            .complete()
            .unwrap_or_else(|_| panic!("original lane recovery"));
        for _ in 0..2 {
            assert!(
                matches!(lane.execute(&fixture.body, &fixture.qc.block_hash, false),
                Err(PublicationError::Retryable(reason)) if reason == "ClockAhead"),
                "uncertified lane must wait at its authenticated effective clock boundary"
            );
            assert!(lane.cache.is_empty());
            assert_eq!(lane.applied.height, 0);
        }
        let original = lane.admission.as_ref().unwrap();
        let batch_pointer = original.batch.transactions.as_ptr();
        let input_pointer = original.body.payload().as_slice().as_ptr();
        assert_eq!(
            original.admitted.as_ref().unwrap().effective_time,
            effective
        );
        clock.rewind(Duration::from_millis(1));
        assert!(matches!(
            lane.execute(&fixture.body, &fixture.qc.block_hash, false),
            Err(PublicationError::Retryable(_))
        ));
        assert_eq!(
            lane.admission.as_ref().unwrap().batch.transactions.as_ptr(),
            batch_pointer
        );
        assert_eq!(
            lane.admission
                .as_ref()
                .unwrap()
                .body
                .payload()
                .as_slice()
                .as_ptr(),
            input_pointer
        );
        clock.set(boundary);
        assert!(
            matches!(lane.execute(&fixture.body, &fixture.qc.block_hash, false), Ok(Some(ExecOutcome::Valid { result, .. })) if result == fixture.qc.result)
        );
        clock.set(Duration::ZERO);
        assert!(
            matches!(lane.execute(&fixture.body, &fixture.qc.block_hash, false), Ok(Some(ExecOutcome::Valid { result, .. })) if result == fixture.qc.result)
        );
        lane.discard(1, &[]);
        assert!(matches!(
            lane.execute(&fixture.body, &fixture.qc.block_hash, false),
            Err(PublicationError::Retryable(_))
        ));
        assert!(
            matches!(lane.execute(&fixture.body, &fixture.qc.block_hash, true), Ok(Some(ExecOutcome::Valid { result, .. })) if result == fixture.qc.result)
        );
        lane.discard(1, &[]);
        assert_eq!(
            lane.prepare(&fixture.body, &fixture.qc).unwrap(),
            Some(fixture.qc.result)
        );
        fixture.store.append(&fixture.body, &fixture.qc).unwrap();
        lane.commit(&fixture.body, &fixture.qc).unwrap();
        let recovered = fixture
            .recovery_with_clock(time)
            .complete()
            .unwrap_or_else(|_| panic!("original lane recovery"));
        assert_eq!(recovered.applied.height, 1);
        assert_eq!(recovered.applied.block_hash, fixture.qc.block_hash);
        assert!(
            recovered
                .applied
                .state
                .view()
                .recent
                .contains_key(&fixture.transaction.hash_as_entrypoint())
        );
    }
}

#[test]
fn signed_lane_clock_wait_cannot_reuse_a_foreign_anchor_identity() {
    let fixture = Fixture::new(true);
    let (_, time) = iroha_primitives::time::TimeSource::new_mock(Duration::ZERO);
    let mut lane = fixture
        .recovery_with_clock(time)
        .complete()
        .unwrap_or_else(|_| panic!("original lane recovery"));
    assert!(matches!(
        lane.execute(&fixture.body, &fixture.qc.block_hash, false),
        Err(PublicationError::Retryable(_))
    ));
    lane.anchors = Arc::new(Anchor(
        HashOf::from_untyped_unchecked(Hash::new(b"foreign applied anchor")),
        fixture.anchor.1.clone(),
    ));
    assert_eq!(
        lane.execute(&fixture.body, &fixture.qc.block_hash, true)
            .unwrap(),
        Some(ExecOutcome::Invalid)
    );
    assert!(lane.admission.is_none());
    assert!(lane.cache.is_empty());
    lane.anchors = fixture.anchor.clone();
    assert!(
        matches!(lane.execute(&fixture.body, &fixture.qc.block_hash, true), Ok(Some(ExecOutcome::Valid { result, .. })) if result == fixture.qc.result)
    );
}

#[test]
fn native_lane_first_prepare_admission_binds_original_source_and_retains_its_charge() {
    use iroha_sumeragi::testing::prepare_signing_request;
    let fixture = Fixture::new(true);
    let mut lane = fixture
        .recovery()
        .complete()
        .unwrap_or_else(|_| panic!("original lane"));
    let Ok(Some(ExecOutcome::Valid { result, admission })) =
        lane.execute(&fixture.body, &fixture.qc.block_hash, false)
    else {
        panic!("genuine native lane admission")
    };
    assert_eq!(admission.result(), result);
    let source = fixture.body.source();
    let request = |instance, epoch, height, hash, result, certified| {
        prepare_signing_request(instance, epoch, height, 0, hash, result, certified)
    };
    let exact = request(
        source.instance(),
        source.config().epoch.id,
        fixture.body.header().height,
        fixture.qc.block_hash,
        result,
        false,
    );
    assert!(admission.check(&exact).is_ok());
    let mut changed_epoch = source.config().epoch.id;
    changed_epoch.context.0[0] ^= 1;
    for changed in [
        request(
            Hash32::ZERO,
            exact.epoch(),
            exact.height(),
            exact.block_hash(),
            result,
            false,
        ),
        request(
            exact.instance(),
            changed_epoch,
            exact.height(),
            exact.block_hash(),
            result,
            false,
        ),
        request(
            exact.instance(),
            exact.epoch(),
            exact.height() + 1,
            exact.block_hash(),
            result,
            false,
        ),
        request(
            exact.instance(),
            exact.epoch(),
            exact.height(),
            Hash32::ZERO,
            result,
            false,
        ),
        request(
            exact.instance(),
            exact.epoch(),
            exact.height(),
            exact.block_hash(),
            Hash32::ZERO,
            false,
        ),
        request(
            exact.instance(),
            exact.epoch(),
            exact.height(),
            Hash32::ZERO,
            result,
            true,
        ),
    ] {
        assert!(
            admission.check(&changed).is_err(),
            "certification never exempts source substitution"
        );
    }
    let reserved = fixture.budget.reserved_bytes();
    lane.discard(exact.height(), &[]);
    assert_eq!(fixture.budget.reserved_bytes(), reserved);
    assert!(admission.check(&exact).is_ok());
    drop(admission);
    assert_eq!(
        fixture.budget.reserved_bytes(),
        reserved - ChargedShared::<LanePrepareAdmission>::allocation_layout().size()
    );
}

#[test]
fn native_lane_first_prepare_owner_refusal_preserves_original_decoded_admission() {
    let fixture = Fixture::new(true);
    let effective = Duration::from_millis(6_001);
    let boundary = effective
        .checked_sub(fixture.record.params.max_clock_drift())
        .expect("fixture effective time exceeds maximum drift");
    let (clock, time) = iroha_primitives::time::TimeSource::new_mock(
        boundary
            .checked_sub(Duration::from_millis(1))
            .expect("fixture boundary exceeds one millisecond"),
    );
    let mut lane = fixture
        .recovery_with_clock(time)
        .complete()
        .unwrap_or_else(|_| panic!("original lane"));
    assert!(matches!(
        lane.execute(&fixture.body, &fixture.qc.block_hash, false),
        Err(PublicationError::Retryable(_))
    ));
    let pointer = lane.admission.as_ref().unwrap().batch.transactions.as_ptr();
    let reserved = fixture.budget.reserved_bytes();
    let bytes = ChargedShared::<LanePrepareAdmission>::allocation_layout().size();
    clock.set(boundary);
    fixture.budget.set_limit_bytes(reserved + bytes - 1);
    for _ in 0..2 {
        let Err(PublicationError::Deferred(original)) =
            lane.execute(&fixture.body, &fixture.qc.block_hash, false)
        else {
            panic!("original first-Prepare owner admission must retain the exact refusal");
        };
        assert!(original.allocation_refusal().is_some());
        assert!(lane.cache.is_empty());
        assert_eq!(
            lane.admission.as_ref().unwrap().batch.transactions.as_ptr(),
            pointer
        );
        assert_eq!(fixture.budget.reserved_bytes(), reserved);
    }
    fixture.budget.set_limit_bytes(reserved + bytes);
    assert!(
        matches!(lane.execute(&fixture.body, &fixture.qc.block_hash, false),
        Ok(Some(ExecOutcome::Valid { result, .. })) if result == fixture.qc.result)
    );
}
