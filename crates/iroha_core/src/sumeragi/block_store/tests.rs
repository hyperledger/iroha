//! Real BLS/model integration of Kura publication and retained read ownership.
use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::{body_read::BodyReadPoll, crypto::BlsCrypto};
use iroha_data_model::{
    block::decode_framed_signed_block,
    sumeragi_finality::{ScheduledSlot, test_fixtures::NativeFinalityFixture},
};
use iroha_sumeragi::{availability::AvailabilityFrame, types::HeightConfig};
struct Schedule {
    instance: Hash32,
    config: Mutex<Option<HeightConfig>>,
}
impl AvailabilitySchedule for Schedule {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn height_config(&self, _height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        Ok(self.config.lock().clone())
    }
}
struct Fixture {
    store: KuraBlockStore,
    schedule: Arc<Schedule>,
    executed: iroha_data_model::block::SharedSignedBlock,
    body: AvailableBody,
    qc: Qc,
}
fn fixture() -> Fixture {
    let fixture = NativeFinalityFixture::new();
    let parent = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("authenticated schedule")
    };
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(
            scheduled
                .epoch
                .committee
                .iter()
                .map(|m| (m.validator.public_key(), m.proof_of_possession.as_slice())),
        )
        .unwrap();
    let instance = fixture.verifier().instance();
    let schedule = Arc::new(Schedule {
        instance,
        config: Mutex::new(Some(scheduled.height_config().unwrap())),
    });
    let budget = AllocationBudget::new(1 << 27);
    let kura = Kura::blank_kura_for_testing();
    kura.store_block(
        iroha_data_model::block::SharedSignedBlock::reserve(&budget)
            .unwrap()
            .initialize(fixture.genesis().clone()),
    )
    .unwrap();
    let mut executed = decode_framed_signed_block(&fixture.latest().block_wire).unwrap();
    let c = executed
        .commit_certificate()
        .unwrap()
        .clone()
        .admit(&budget)
        .unwrap();
    executed.set_commit_certificate(Some(c));
    let executed = iroha_data_model::block::SharedSignedBlock::reserve(&budget)
        .unwrap()
        .initialize(executed);
    let store = KuraBlockStore::new(kura, crypto, 1, Staging::new(), budget, schedule.clone());
    let mut read = CommittedRead::new(
        executed.clone(),
        2,
        store.execution_budget.clone(),
        store.hasher.clone(),
        schedule.clone(),
    );
    let (body, qc) = read.poll().unwrap();
    Fixture {
        store,
        schedule,
        executed,
        body,
        qc,
    }
}
fn stage(f: &Fixture, executed: iroha_data_model::block::SharedSignedBlock) {
    f.store.staging.stage(StagedBlock {
        block_hash: f.qc.block_hash,
        executed,
    });
}
#[test]
fn exact_original_frame_publishes_replays_and_serves_original_availability() {
    let f = fixture();
    assert_eq!(f.store.height(), 1);
    assert!(f.store.entry(1).unwrap().is_none());
    assert!(f.store.tip().unwrap().is_none());
    assert!(f.store.append(&f.body, &f.qc).is_err());
    assert_eq!(f.store.height(), 1);
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    assert_eq!(f.store.height(), 2);
    let original = f
        .store
        .kura
        .get_block(NonZeroUsize::new(2).unwrap(), &f.store.execution_budget)
        .expect("original block read attempt")
        .unwrap();
    assert_eq!(
        original.encode_wire().unwrap(),
        f.executed.encode_wire().unwrap()
    );
    f.store.append(&f.body, &f.qc).unwrap();
    let (body, qc) = f.store.committed_body(2).unwrap().unwrap();
    assert_eq!(body, f.body);
    assert_eq!(qc, f.qc);
    assert_eq!(body.source(), f.body.source());
    let entry = f.store.entry(2).unwrap().unwrap();
    assert_eq!(entry.manifest.header, *f.body.header());
    assert_eq!(entry.manifest.availability, *f.body.availability());
    assert_eq!(entry.commit_qc, f.qc);
    assert_eq!(
        f.store.certified(2).unwrap().unwrap(),
        (f.body.header().clone(), f.qc.clone())
    );
    assert_eq!(f.store.header(2).unwrap(), Some(f.body.header().clone()));
    assert_eq!(f.store.tip().unwrap(), Some(entry.clone()));
    assert_eq!(
        f.store.recent_headers(2).unwrap(),
        vec![f.body.header().clone()]
    );
    assert!(f.store.recent_headers(0).unwrap().is_empty());
    assert_eq!(f.store.entries(2, 4, 1).unwrap(), vec![entry]);
    assert!(f.store.entry(3).unwrap().is_none());
    f.store.staging.clear();
    assert!(f.store.staging.get(&f.qc.block_hash).is_none());
}
#[test]
fn independently_changed_authority_rejects_original_body_before_any_publication() {
    let f = fixture();
    stage(&f, f.executed.clone());
    let mut config = f.body.source().config().clone();
    config.params.block_time += 1;
    *f.schedule.config.lock() = Some(config);
    let independent =
        committed_read::certified_source(&*f.schedule, &*f.store.hasher, 2, f.body.header(), &f.qc)
            .unwrap();
    assert_ne!(
        &independent,
        f.body.source(),
        "valid exact QC does not authorize relabelling full body authority"
    );
    assert_eq!(
        f.store.append(&f.body, &f.qc).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(f.store.height(), 1);
    assert!(f.store.begin_read(f.body.source().clone()).is_err());
}
#[test]
fn corrupt_availability_is_an_error_not_missing_or_served_metadata() {
    let f = fixture();
    let c = f.executed.commit_certificate().unwrap();
    let mut table = c.availability().to_vec();
    *table.last_mut().unwrap() ^= 1;
    let block = f.executed.as_ref().clone().with_commit_certificate(Some(
        CommitCertificate::from_untrusted_parts(
            c.consensus_header().to_vec(),
            c.commit_qc().to_vec(),
            c.result_preimage().to_vec(),
            table,
        ),
    ));
    f.store
        .kura
        .store_block(
            iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
                .unwrap()
                .initialize(block),
        )
        .unwrap();
    assert_eq!(
        f.store.entry(2).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert!(f.store.tip().is_err());
    assert!(f.store.header(2).is_err());
    assert!(f.store.entries(2, 5, u32::MAX).is_err());
    assert!(
        f.store.read.lock().is_none(),
        "terminal corruption cannot pin unrelated reads"
    );
}
#[test]
fn retry_retains_original_read_and_funding_even_when_another_height_is_requested() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let held = f.store.execution_budget.reserved_bytes();
    f.store.execution_budget.set_limit_bytes(held);
    assert_eq!(
        f.store.committed_body(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        f.store.committed_body(3).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.store.read.lock().as_ref().unwrap().height(), 2);
    assert_eq!(f.store.execution_budget.reserved_bytes(), held);
    f.store.execution_budget.set_limit_bytes(1 << 27);
    let (body, qc) = f.store.committed_body(2).unwrap().unwrap();
    assert_eq!(body, f.body);
    assert_eq!(qc, f.qc);
    assert!(f.store.read.lock().is_none());
}
#[test]
fn missing_authority_retains_decoded_source_and_resumes_without_replacement() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let config = f.schedule.config.lock().take();
    assert_eq!(
        f.store.entry(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    let reserved = f.store.execution_budget.reserved_bytes();
    assert_eq!(
        f.store.entry(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(reserved, f.store.execution_budget.reserved_bytes());
    *f.schedule.config.lock() = config;
    assert_eq!(f.store.entry(2).unwrap().unwrap().commit_qc, f.qc);
}
#[test]
fn independent_read_transfers_untrusted_restoration_and_rejects_foreign_pool() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let mut job = f.store.begin_read(f.body.source().clone()).unwrap();
    assert!(matches!(
        job.poll(&AllocationBudget::new(1 << 27)),
        Err(BodyReadError::ForeignBudget)
    ));
    let BodyReadPoll::Ready(restoration) = job.poll(&f.store.execution_budget).unwrap() else {
        panic!("original restoration")
    };
    let body = restoration
        .complete(&f.store.execution_budget, &*f.store.hasher)
        .unwrap_or_else(|_| panic!("full original availability"));
    assert_eq!(body, f.body);
}

#[test]
fn kura_body_reader_competing_hash_at_committed_height_is_verified_absence() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let source = f
        .store
        .availability_source(2, Hash32([0x91; 32]))
        .unwrap()
        .unwrap();
    assert_ne!(source.block_hash(), f.body.source().block_hash());
    let mut job = f.store.begin_read(source.clone()).unwrap();
    assert_eq!(job.source(), &source);
    assert!(matches!(
        job.poll(&AllocationBudget::new(1 << 27)),
        Err(BodyReadError::ForeignBudget)
    ));
    let reserved = f.store.execution_budget.reserved_bytes();
    let table_len = f.body.availability().as_slice().len();
    f.store
        .execution_budget
        .set_limit_bytes(reserved + table_len);
    assert!(matches!(
        job.poll(&f.store.execution_budget),
        Ok(BodyReadPoll::Pending(_))
    ));
    let held = f.store.execution_budget.reserved_bytes();
    assert_eq!(held, reserved + table_len);
    assert!(matches!(
        job.poll(&f.store.execution_budget),
        Ok(BodyReadPoll::Pending(_))
    ));
    assert_eq!(f.store.execution_budget.reserved_bytes(), held);
    assert_eq!(job.source(), &source);
    f.store.execution_budget.set_limit_bytes(1 << 27);
    assert!(matches!(
        job.poll(&f.store.execution_budget),
        Ok(BodyReadPoll::Absent)
    ));
    assert!(matches!(
        job.poll(&f.store.execution_budget),
        Err(BodyReadError::Completed)
    ));
    assert_eq!(f.store.execution_budget.reserved_bytes(), reserved);

    let mut exact = f.store.begin_read(f.body.source().clone()).unwrap();
    let BodyReadPoll::Ready(restoration) = exact.poll(&f.store.execution_budget).unwrap() else {
        panic!("canonical hash still transfers its exact restoration")
    };
    let body = restoration
        .complete(&f.store.execution_budget, &*f.store.hasher)
        .unwrap_or_else(|_| panic!("original signed availability"));
    assert_eq!(body, f.body);
}

#[test]
fn kura_body_reader_competing_hash_never_hides_corrupt_stored_certificates() {
    for mutation in 0..3 {
        let f = fixture();
        let old = f.executed.commit_certificate().unwrap();
        let mut qc = f.qc.clone();
        let mut result = old.result_preimage().to_vec();
        let original: AvailabilityFrame = norito::decode_canonical(old.availability()).unwrap();
        let mut table = original.as_slice().to_vec();
        match mutation {
            0 => qc.agg_sig.0[0] ^= 1,
            1 => result[0] ^= 1,
            2 => *table.last_mut().unwrap() ^= 1,
            _ => unreachable!(),
        }
        let table = AvailabilityFrame::from_untrusted(table).unwrap();
        let certificate = commit_certificate(
            f.body.header(),
            &qc,
            result,
            norito::encode_canonical(&table).unwrap(),
        )
        .unwrap();
        f.store
            .kura
            .store_block(
                iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
                    .unwrap()
                    .initialize(
                        f.executed
                            .as_ref()
                            .clone()
                            .with_commit_certificate(Some(certificate)),
                    ),
            )
            .unwrap();
        let source = f
            .store
            .availability_source(2, Hash32([0x91; 32]))
            .unwrap()
            .unwrap();
        let mut job = f.store.begin_read(source.clone()).unwrap();
        for _ in 0..2 {
            assert!(job.poll(&f.store.execution_budget).is_err());
            assert_eq!(job.source(), &source);
        }
    }
}

#[test]
fn invalid_full_qc_or_staged_certificate_never_reaches_kura() {
    let f = fixture();
    stage(&f, f.executed.clone());
    let mut qc = f.qc.clone();
    qc.agg_sig.0[0] ^= 1;
    assert_eq!(
        f.store.append(&f.body, &qc).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(f.store.height(), 1);
    let c = f.executed.commit_certificate().unwrap();
    let mut result = c.result_preimage().to_vec();
    result[0] ^= 1;
    let bad = f.executed.as_ref().clone().with_commit_certificate(Some(
        CommitCertificate::from_untrusted_parts(
            c.consensus_header().to_vec(),
            c.commit_qc().to_vec(),
            result,
            c.availability().to_vec(),
        )
        .admit(&f.store.execution_budget)
        .unwrap(),
    ));
    stage(
        &f,
        iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
            .unwrap()
            .initialize(bad),
    );
    assert!(f.store.append(&f.body, &f.qc).is_err());
    assert_eq!(f.store.height(), 1);
    let foreign = AllocationBudget::new(1 << 27);
    let bad = f.executed.as_ref().clone().with_commit_certificate(Some(
        CommitCertificate::from_untrusted_parts(
            c.consensus_header().to_vec(),
            c.commit_qc().to_vec(),
            c.result_preimage().to_vec(),
            c.availability().to_vec(),
        )
        .admit(&foreign)
        .unwrap(),
    ));
    stage(
        &f,
        iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
            .unwrap()
            .initialize(bad),
    );
    assert!(f.store.append(&f.body, &f.qc).is_err());
    assert_eq!(f.store.height(), 1);
}
#[test]
fn borrowed_comparison_covers_complete_executed_projection_and_canonical_helpers() {
    let f = fixture();
    let bytes = f.body.payload().as_slice();
    assert!(publication::matches_payload(&f.executed, bytes).unwrap());
    assert!(!publication::matches_payload(&f.executed, &bytes[..bytes.len() - 1]).unwrap());
    let mut bad = bytes.to_vec();
    bad[0] ^= 1;
    assert!(!publication::matches_payload(&f.executed, &bad).unwrap());
    assert_eq!(
        f.executed
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection")
            .encode_wire()
            .unwrap(),
        bytes
    );
    let c = f.executed.commit_certificate().unwrap();
    assert_eq!(
        decode_certificate(c).unwrap(),
        (f.body.header().clone(), f.qc.clone())
    );
    let made = commit_certificate(
        f.body.header(),
        &f.qc,
        c.result_preimage().to_vec(),
        c.availability().to_vec(),
    )
    .unwrap();
    assert_eq!(made, *c);
}

#[test]
fn empty_payload_header_cannot_restore_committed_body() {
    let f = fixture();
    let certificate = f.executed.commit_certificate().unwrap();
    let mut header = f.body.header().clone();
    header.payload_len = 0;
    let certificate = commit_certificate(
        &header,
        &f.qc,
        certificate.result_preimage().to_vec(),
        certificate.availability().to_vec(),
    )
    .unwrap();
    f.store
        .kura
        .store_block(
            iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
                .unwrap()
                .initialize(
                    f.executed
                        .as_ref()
                        .clone()
                        .with_commit_certificate(Some(certificate)),
                ),
        )
        .unwrap();
    assert_eq!(
        f.store.committed_body(2).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData,
    );
}

#[test]
fn refused_certificate_read_observation_preserves_original_source_and_table() {
    let f = fixture();
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let source = f
        .store
        .kura
        .get_block(NonZeroUsize::new(2).unwrap(), &f.store.execution_budget)
        .expect("original block read attempt")
        .unwrap();
    let budget = &f.store.execution_budget;
    let limit = budget.limit_bytes();
    let reserved = budget.reserved_bytes();
    let table_len = f.body.availability().as_slice().len();
    budget.set_limit_bytes(reserved + table_len);
    assert_eq!(
        f.store.certified(2).unwrap_err().io_kind(),
        io::ErrorKind::WouldBlock
    );
    let owners = f.store.pending_certificate_read_for_test().unwrap();
    assert_eq!(owners.0, std::ptr::from_ref(source.as_ref()));
    assert!(owners.1.is_some());
    assert_eq!(budget.reserved_bytes(), reserved + table_len);
    for height in [2, 3, 2] {
        assert_eq!(
            f.store.certified(height).unwrap_err().io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(f.store.pending_certificate_read_for_test(), Some(owners));
        assert_eq!(budget.reserved_bytes(), reserved + table_len);
    }
    budget.set_limit_bytes(limit);
    let (body, qc) = f.store.committed_body(2).unwrap().unwrap();
    assert_eq!(body.availability().as_slice().as_ptr(), owners.1.unwrap());
    assert_eq!(qc, f.qc);
    assert!(f.store.pending_certificate_read_for_test().is_none());
}

#[test]
fn staging_preserves_original_identity_across_lookup_and_clear() {
    let f = fixture();
    let original = StagedBlock {
        block_hash: f.qc.block_hash,
        executed: f.executed.clone(),
    };
    assert!(f.store.staging().get(&f.qc.block_hash).is_none());
    f.store.staging().stage(original.clone());
    assert!(f.store.staging().get(&Hash32([0x99; 32])).is_none());
    let first = f.store.staging().get(&f.qc.block_hash).unwrap();
    let retry = f.store.staging().get(&f.qc.block_hash).unwrap();
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &first.executed,
        &original.executed
    ));
    assert_eq!(first.block_hash, retry.block_hash);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &first.executed,
        &retry.executed
    ));
    assert!(std::ptr::eq(
        first.executed.commit_certificate().unwrap(),
        retry.executed.commit_certificate().unwrap()
    ));
    f.store.staging().clear();
    assert!(f.store.staging().get(&f.qc.block_hash).is_none());
    assert_eq!(first.block_hash, f.qc.block_hash);
}
#[test]
fn real_valid_future_certificate_cannot_skip_a_height_and_reopening_keeps_original_chain() {
    let f = fixture();
    let mut chain = NativeFinalityFixture::new();
    let block = chain.block_with_submitted_work(chain.next_header());
    chain.certify(block);
    let third = iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
        .unwrap()
        .initialize(decode_framed_signed_block(&chain.latest().block_wire).unwrap());
    let mut read = CommittedRead::new(
        third,
        3,
        f.store.execution_budget.clone(),
        f.store.hasher.clone(),
        f.schedule.clone(),
    );
    let (body, qc) = read.poll().unwrap();
    assert_eq!(
        f.store.append(&body, &qc).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(f.store.height(), 1);
    stage(&f, f.executed.clone());
    f.store.append(&f.body, &f.qc).unwrap();
    let reopened = KuraBlockStore::new(
        f.store.kura.clone(),
        f.store.hasher.clone(),
        1,
        Staging::new(),
        f.store.execution_budget.clone(),
        f.schedule.clone(),
    );
    assert_eq!(reopened.height(), 2);
    assert_eq!(
        reopened.entries(2, 10, u32::MAX).unwrap(),
        f.store.entries(2, 10, u32::MAX).unwrap()
    );
}
#[test]
fn untrusted_certificate_and_mismatching_staged_payload_are_never_written() {
    let f = fixture();
    let c = f.executed.commit_certificate().unwrap();
    let untrusted = CommitCertificate::from_untrusted_parts(
        c.consensus_header().to_vec(),
        c.commit_qc().to_vec(),
        c.result_preimage().to_vec(),
        c.availability().to_vec(),
    );
    stage(
        &f,
        iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
            .unwrap()
            .initialize(
                f.executed
                    .as_ref()
                    .clone()
                    .with_commit_certificate(Some(untrusted)),
            ),
    );
    assert!(f.store.append(&f.body, &f.qc).is_err());
    assert_eq!(f.store.height(), 1);
    let mut other = NativeFinalityFixture::start("portable-native-fixture");
    let mut header = other.next_header();
    header.creation_time_ms += 17;
    let different = other.block_with_submitted_work(header);
    other.certify(different);
    let mut mismatching = decode_framed_signed_block(&other.latest().block_wire).unwrap();
    assert_eq!(mismatching.header().height().get(), 2);
    assert!(!publication::matches_payload(&mismatching, f.body.payload().as_slice()).unwrap());
    // Keep the original valid certificate but provide another executed frame: it must fail
    // before publication even though the certificate and pool themselves are admitted.
    mismatching.set_commit_certificate(Some(c.clone()));
    stage(
        &f,
        iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
            .unwrap()
            .initialize(mismatching),
    );
    assert!(f.store.append(&f.body, &f.qc).is_err());
    assert_eq!(f.store.height(), 1);
    let garbage = CommitCertificate::from_untrusted_parts(vec![1, 2, 3], vec![], vec![], vec![]);
    assert!(decode_certificate(&garbage).is_err());
    let uncertified = f.executed.as_ref().clone().with_commit_certificate(None);
    f.store
        .kura
        .store_block(
            iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
                .unwrap()
                .initialize(uncertified),
        )
        .unwrap();
    assert_eq!(
        f.store.entry(2).unwrap_err().io_kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn review_changed_executed_result_must_not_publish_under_original_certificate() {
    let f = fixture();
    let mut changed = f.executed.as_ref().clone();
    changed
        .set_execution_outputs(
            changed.execution_outputs().to_vec(),
            changed
                .committed_fragment_count()
                .unwrap()
                .checked_add(1)
                .unwrap(),
            changed.fastpq_transcripts().clone(),
            changed.axt_envelopes().unwrap_or_default().to_vec(),
            changed.axt_policy_snapshot().unwrap().clone(),
            changed.axt_transitioned_dataspaces().unwrap().clone(),
            &iroha_data_model::block::output_budget::ExecutionOutputLimits {
                max_outputs: 1024,
                max_output_bytes: 16 * 1024 * 1024,
                max_total_output_bytes: 128 * 1024 * 1024,
                max_executed_wire_bytes:
                    iroha_data_model::block::consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES,
            },
        )
        .unwrap();
    assert_eq!(
        changed.commit_certificate(),
        f.executed.commit_certificate()
    );
    assert!(changed.has_results());
    assert!(publication::matches_payload(&changed, f.body.payload().as_slice()).unwrap());
    let commitment = iroha_data_model::sumeragi_finality::ExecutionResultCommitment::decode(
        changed.commit_certificate().unwrap().result_preimage(),
    )
    .unwrap();
    let (len, hash) = changed.executed_block_wire_identity().unwrap();
    assert_ne!(
        (
            commitment.execution.executed_block_wire_len,
            commitment.execution.executed_block_wire_hash
        ),
        (len, hash)
    );
    stage(
        &f,
        iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
            .unwrap()
            .initialize(changed),
    );
    assert!(
        f.store.append(&f.body, &f.qc).is_err(),
        "the actual changed execution is not the result authenticated by the original QC"
    );
    assert_eq!(f.store.height(), 1);
}
#[test]
fn review_changed_executed_result_must_not_be_served_from_committed_storage() {
    let f = fixture();
    let mut changed = f.executed.as_ref().clone();
    changed
        .set_execution_outputs(
            changed.execution_outputs().to_vec(),
            changed
                .committed_fragment_count()
                .unwrap()
                .checked_add(1)
                .unwrap(),
            changed.fastpq_transcripts().clone(),
            changed.axt_envelopes().unwrap_or_default().to_vec(),
            changed.axt_policy_snapshot().unwrap().clone(),
            changed.axt_transitioned_dataspaces().unwrap().clone(),
            &iroha_data_model::block::output_budget::ExecutionOutputLimits {
                max_outputs: 1024,
                max_output_bytes: 16 * 1024 * 1024,
                max_total_output_bytes: 128 * 1024 * 1024,
                max_executed_wire_bytes:
                    iroha_data_model::block::consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES,
            },
        )
        .unwrap();
    assert_eq!(
        changed.commit_certificate(),
        f.executed.commit_certificate()
    );
    assert!(changed.has_results());
    assert!(publication::matches_payload(&changed, f.body.payload().as_slice()).unwrap());
    let commitment = iroha_data_model::sumeragi_finality::ExecutionResultCommitment::decode(
        changed.commit_certificate().unwrap().result_preimage(),
    )
    .unwrap();
    let (len, hash) = changed.executed_block_wire_identity().unwrap();
    assert_ne!(
        (
            commitment.execution.executed_block_wire_len,
            commitment.execution.executed_block_wire_hash
        ),
        (len, hash)
    );
    f.store
        .kura
        .store_block(
            iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
                .unwrap()
                .initialize(changed),
        )
        .unwrap();
    assert!(
        f.store.committed_body(2).is_err(),
        "changed stored execution is not the result authenticated by its original QC"
    );
}

// The source is signed before expansion. Never derive its bytes with the borrowed
// projection under test: that would sign the same incorrect suffix and hide the bug.
// Outputs are explicit synthetic codec fixtures, not evidence of World execution.
fn merged_execution_fixture() -> Fixture {
    use crate::sumeragi::crypto::KeyPairSigner;
    use iroha_allocation::ChargedBuffer;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        block::{BlockExecutionContextBundle, ExternalExecutionContext, builder::BlockBuilder},
        sumeragi_finality::ExecutionResultCommitment,
        sumeragi_lanes::{SumeragiLaneMerge, SumeragiLaneMergeSection},
        transaction::signed::TransactionEntrypoint,
    };
    use iroha_model_base::topology::{DataSpaceId, LaneId};
    use iroha_sumeragi::{
        availability::{PayloadAuthoring, PayloadBytes},
        crypto::Signer,
        preimage::payload_hash,
        types::Bitmap,
    };

    let mut f = fixture();
    let own = f.executed.external_transactions().next().unwrap().clone();
    let mut context = BlockExecutionContextBundle::new(vec![ExternalExecutionContext::new(
        own.hash_as_entrypoint(),
        LaneId::new(0),
        DataSpaceId::new(0),
    )]);
    context.lane_merge = Some(SumeragiLaneMergeSection {
        merges: vec![SumeragiLaneMerge {
            lane: LaneId::new(16),
            incarnation: [1; 32],
            from: 1,
            to: 2,
            tip_hash: [2; 32],
            tip_result: [3; 32],
        }],
        time_floor_ms: 0,
        merged_count: 0,
    });
    let mut builder = BlockBuilder::new(f.executed.header());
    builder.push_transaction(own);
    builder.set_execution_context(Some(context));
    let proposal = builder.build(Default::default());
    let original_wire = proposal.encode_wire().unwrap();

    // Another genuinely signed transaction with a distinct creation time. The
    // descriptor and outputs are structural fixtures, not a lane-finality claim.
    let chain = NativeFinalityFixture::start("portable-native-fixture");
    let mut other_header = chain.next_header();
    other_header.creation_time_ms += 1;
    let other = chain.block_with_submitted_work(other_header);
    let merged =
        TransactionEntrypoint::External(other.external_transactions().next().unwrap().clone());
    let merged_context =
        ExternalExecutionContext::new(merged.hash(), LaneId::new(16), DataSpaceId::new(0));
    let mut executed = proposal
        .with_merged_entrypoints(vec![merged], vec![merged_context])
        .expect("append the execution-only lane suffix");
    NativeFinalityFixture::install_network_results(
        &mut executed,
        vec![Ok(Default::default()), Ok(Default::default())],
    );
    assert_eq!(executed.merged_entrypoint_count(), 1);
    assert_eq!(executed.external_transactions().len(), 2);
    assert_eq!(executed.execution_outputs().len(), 2);
    assert_eq!(
        executed
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection")
            .encode_wire()
            .unwrap(),
        original_wire,
    );

    let config = f.body.source().config().clone();
    let mut signers: Vec<_> = (1..=4)
        .map(|seed| {
            KeyPairSigner::new(&KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal)).unwrap()
        })
        .collect();
    signers.sort_by(|a, b| a.public_key().as_bytes().cmp(b.public_key().as_bytes()));
    assert_eq!(
        signers.iter().map(Signer::public_key).collect::<Vec<_>>(),
        config.committee.members().iter().collect::<Vec<_>>(),
    );
    let budget = &f.store.execution_budget;
    let mut backing = ChargedBuffer::new(original_wire.len(), budget).unwrap();
    for byte in &original_wire {
        backing.push_reserved(*byte);
    }
    let payload = PayloadBytes::from_charged(backing, budget)
        .unwrap_or_else(|_| panic!("original proposal backing admission"));
    let mut header = f.body.header().clone();
    header.payload_len = original_wire.len().try_into().unwrap();
    header.payload_hash = payload_hash(&*f.store.hasher, &original_wire);
    header.availability_digest = Hash32::ZERO;
    let signer = &signers[usize::try_from(header.proposer).unwrap()];
    let authored = PayloadAuthoring::new(header, payload)
        .complete(
            f.schedule.instance,
            &config,
            budget,
            &*f.store.hasher,
            signer,
        )
        .unwrap_or_else(|_| panic!("original signed availability authoring"));
    assert_eq!(authored.body.payload().as_slice(), original_wire);

    let mut result = ExecutionResultCommitment::decode(
        f.executed.commit_certificate().unwrap().result_preimage(),
    )
    .unwrap();
    let (len, hash) = executed.executed_block_wire_identity().unwrap();
    result.execution.executed_block_wire_len = len;
    result.execution.executed_block_wire_hash = hash;
    result.execution.transaction_input_commitment = executed.network_input_merkle_commitment();
    result.execution.transaction_output_commitment = executed.output_merkle_commitment();
    result.validate().unwrap();
    let mut qc = f.qc.clone();
    qc.block_hash = authored.body.header().hash(&*f.store.hasher);
    qc.result = result.result().unwrap();
    qc.signers = Bitmap::from_indices(4, [0, 1, 2]).unwrap();
    let shares: Vec<_> = signers[..3]
        .iter()
        .map(|signer| signer.sign(&qc.preimage()))
        .collect();
    qc.agg_sig = f.store.hasher.aggregate(&shares);
    let certificate = commit_certificate(
        authored.body.header(),
        &qc,
        result.preimage().unwrap(),
        norito::encode_canonical(authored.body.availability()).unwrap(),
    )
    .unwrap()
    .admit(budget)
    .unwrap();
    executed.set_commit_certificate(Some(certificate));
    execution::validate(&executed).unwrap();
    f.executed = iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
        .unwrap()
        .initialize(executed);
    f.body = authored.body;
    f.qc = qc;
    f
}

#[test]
fn merged_execution_publishes_the_exact_original_signed_proposal() {
    let f = merged_execution_fixture();
    stage(&f, f.executed.clone());
    f.store
        .append(&f.body, &f.qc)
        .expect("execution-only merged inputs must not change the signed proposal");
    assert_eq!(f.store.height(), 2);
    let stored = f
        .store
        .kura
        .get_block(NonZeroUsize::new(2).unwrap(), &f.store.execution_budget)
        .expect("original block read attempt")
        .unwrap();
    assert_eq!(
        stored.encode_wire().unwrap(),
        f.executed.encode_wire().unwrap()
    );
    let (body, qc) = f.store.committed_body(2).unwrap().unwrap();
    assert_eq!(body, f.body);
    assert_eq!(body.source(), f.body.source());
    assert_eq!(body.availability(), f.body.availability());
    assert_eq!(body.payload().as_slice(), f.body.payload().as_slice());
    assert_eq!(qc, f.qc);
    f.store.append(&f.body, &f.qc).unwrap();
    assert_eq!(f.store.height(), 2);
}

#[test]
fn merged_execution_cold_read_restores_original_signed_availability() {
    let f = merged_execution_fixture();
    // Install the authentic complete stored frame directly so this test reaches
    // cold restoration independently of the publication comparison regression.
    f.store.kura.store_block(f.executed.clone()).unwrap();
    let reopened = KuraBlockStore::new(
        f.store.kura.clone(),
        f.store.hasher.clone(),
        1,
        Staging::new(),
        f.store.execution_budget.clone(),
        f.schedule.clone(),
    );
    let (body, qc) = reopened
        .committed_body(2)
        .expect("cold projection must remove execution-only merged inputs")
        .unwrap();
    assert_eq!(body, f.body);
    assert_eq!(body.source(), f.body.source());
    assert_eq!(body.availability(), f.body.availability());
    assert_eq!(body.payload().as_slice(), f.body.payload().as_slice());
    assert_eq!(qc, f.qc);
    assert_eq!(
        reopened.certified(2).unwrap().unwrap(),
        (f.body.header().clone(), f.qc)
    );
}

#[test]
fn changed_merged_execution_suffix_cannot_use_the_original_result_certificate() {
    use iroha_data_model::{
        block::ExternalExecutionContext, transaction::signed::TransactionEntrypoint,
    };
    use iroha_model_base::topology::{DataSpaceId, LaneId};

    let f = merged_execution_fixture();
    let chain = NativeFinalityFixture::start("portable-native-fixture");
    let mut header = chain.next_header();
    header.creation_time_ms += 2;
    let other = chain.block_with_submitted_work(header);
    let replacement =
        TransactionEntrypoint::External(other.external_transactions().next().unwrap().clone());
    let context =
        ExternalExecutionContext::new(replacement.hash(), LaneId::new(16), DataSpaceId::new(0));
    let mut changed = f
        .executed
        .canonical_resultless_proposal()
        .expect("valid fixture proposal projection")
        .with_merged_entrypoints(vec![replacement], vec![context])
        .unwrap();
    NativeFinalityFixture::install_network_results(
        &mut changed,
        vec![Ok(Default::default()), Ok(Default::default())],
    );
    changed.set_commit_certificate(f.executed.commit_certificate().cloned());
    assert_eq!(changed.merged_entrypoint_count(), 1);
    assert_ne!(
        changed.executed_block_wire_identity().unwrap(),
        f.executed.executed_block_wire_identity().unwrap(),
    );
    assert!(publication::matches_payload(&changed, f.body.payload().as_slice()).unwrap());
    assert!(execution::validate(&changed).is_err());
    let changed = iroha_data_model::block::SharedSignedBlock::reserve(&f.store.execution_budget)
        .unwrap()
        .initialize(changed);
    stage(&f, changed.clone());
    assert!(f.store.append(&f.body, &f.qc).is_err());
    assert_eq!(f.store.height(), 1);
    f.store.kura.store_block(changed).unwrap();
    assert!(f.store.committed_body(2).is_err());
}
