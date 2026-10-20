//! Actual signed model fixtures projected through the retained stored-body boundary.

use super::super::certificate_read::{CertificateRead, CertificateReadError};
use super::*;
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::crypto::BlsCrypto;
use iroha_data_model::{
    block::{CommitCertificate, decode_framed_signed_block},
    sumeragi_finality::{ScheduledSlot, test_fixtures::NativeFinalityFixture},
};
use iroha_sumeragi::{availability::AvailabilityFrame, types::Hash32};
use std::sync::Arc;

/// Raw model fixtures exercise decode and projection independently of finality.
/// Production slot readers own their decoding, certified authority and absence;
/// this fixture delegates to those same canonical engines without claiming custody.
struct FixtureRead {
    source: AvailabilitySource,
    budget: AllocationBudget,
    crypto: SharedCrypto,
    root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    certificate: Option<CertificateRead>,
    body: Option<StoredBodyRead>,
    absent_consumed: bool,
}
impl FixtureRead {
    fn new(
        source: AvailabilitySource,
        block: Option<iroha_data_model::block::SharedSignedBlock>,
        budget: AllocationBudget,
        crypto: SharedCrypto,
        root_scope: iroha_data_model::block::consensus::SumeragiRootScope,
    ) -> Self {
        let certificate = block.map(|block| CertificateRead::new(block, budget.clone()));
        Self {
            source,
            budget,
            crypto,
            root_scope,
            certificate,
            body: None,
            absent_consumed: false,
        }
    }
    fn body(&self) -> &StoredBodyRead {
        self.body
            .as_ref()
            .expect("original decoded fixture projection")
    }
}
impl BodyReadJob for FixtureRead {
    fn source(&self) -> &AvailabilitySource {
        &self.source
    }
    fn poll(&mut self, budget: &AllocationBudget) -> Result<BodyReadPoll, BodyReadError> {
        if !self.budget.same_pool(budget) {
            return Err(BodyReadError::ForeignBudget);
        }
        if self.absent_consumed {
            return Err(BodyReadError::Completed);
        }
        if let Some(job) = self.certificate.take() {
            match job.complete(budget) {
                Ok(decoded) => {
                    self.body = Some(StoredBodyRead::from_decoded(
                        self.source.clone(),
                        decoded,
                        budget.clone(),
                        self.crypto.clone(),
                        self.root_scope,
                    ))
                }
                Err((job, error)) => {
                    self.certificate = Some(job);
                    return match error {
                        CertificateReadError::ForeignBudget => Err(BodyReadError::ForeignBudget),
                        CertificateReadError::MissingCertificate => {
                            Err(BodyReadError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "stored block has no certificate",
                            )))
                        }
                        CertificateReadError::Decode(error) => {
                            Err(BodyReadError::from_decode(error))
                        }
                        CertificateReadError::Canonical(original) => {
                            Err(BodyReadError::from_attempt(
                                crate::execution_attempt::canonical_decode_attempt_error(
                                    original,
                                    |error| io::Error::new(io::ErrorKind::InvalidData, error),
                                ),
                            ))
                        }
                        CertificateReadError::Admission(error) if error.is_local_refusal() => {
                            Ok(BodyReadPoll::Pending(error))
                        }
                        CertificateReadError::Admission(error) => {
                            Err(BodyReadError::Admission(error))
                        }
                    };
                }
            }
        }
        if let Some(body) = &mut self.body {
            body.poll(budget)
        } else {
            self.absent_consumed = true;
            Ok(BodyReadPoll::Absent)
        }
    }
}

fn fixture() -> (
    iroha_data_model::block::SharedSignedBlock,
    AvailabilitySource,
    SharedCrypto,
    iroha_data_model::block::consensus::SumeragiRootScope,
) {
    let fixture = NativeFinalityFixture::new();
    let parent = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("authenticated next fixture authority");
    };
    let source = crate::block::reserve_block_for_tests()
        .initialize(decode_framed_signed_block(&fixture.latest().block_wire).unwrap());
    let header: iroha_sumeragi::message::BlockHeader =
        norito::decode_canonical(source.commit_certificate().unwrap().consensus_header()).unwrap();
    let crypto: SharedCrypto = Arc::new(BlsCrypto::new());
    let authority = AvailabilitySource::new(
        fixture.verifier().instance(),
        2,
        header.hash(&*crypto),
        scheduled.height_config().unwrap(),
    )
    .unwrap();
    (source, authority, crypto, fixture.root_scope())
}

#[test]
fn stored_body_retains_original_certificate_and_projected_payload_across_refusals() {
    let (block, source, crypto, root_scope) = fixture();
    let measure = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(block.clone(), measure.clone())
        .complete(&measure)
        .unwrap_or_else(|_| panic!("measure actual decoded artifact"));
    let decoded_size = measure.reserved_bytes();
    drop(decoded);
    assert_eq!(measure.reserved_bytes(), 0);
    let budget = AllocationBudget::new(0);
    let mut read = FixtureRead::new(
        source.clone(),
        Some(block.clone()),
        budget.clone(),
        crypto.clone(),
        root_scope,
    );
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    assert_eq!(read.source(), &source);
    let job = read.certificate.as_ref().expect("same certificate owner");
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &block
    ));

    budget.set_limit_bytes(decoded_size);
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    let Stage::Projecting(job) = &read.body().stage else {
        panic!("one funded projection")
    };
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &job.source().source,
        &block
    ));
    let table_pointer = job.source().availability.as_slice().as_ptr();
    let payload_len = block.resultless_proposal_wire_len().unwrap();
    budget.set_limit_bytes(decoded_size + payload_len);
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    let held = budget.reserved_bytes();
    assert_eq!(held, decoded_size + payload_len);
    assert!(matches!(read.poll(&budget), Ok(BodyReadPoll::Pending(_))));
    assert_eq!(budget.reserved_bytes(), held);
    let Stage::Projecting(job) = &read.body().stage else {
        panic!("same encoded projection")
    };
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &job.source().source,
        &block
    ));
    assert_eq!(job.source().availability.as_slice().as_ptr(), table_pointer);

    budget.set_limit_bytes(1 << 25);
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("original exact body")
    };
    assert_eq!(restoration.source(), &source);
    assert!(matches!(read.poll(&budget), Err(BodyReadError::Completed)));
    let body = restoration
        .complete(&budget, &*crypto)
        .unwrap_or_else(|_| panic!("real signatures and full codeword verify"));
    assert_eq!(body.availability().as_slice().as_ptr(), table_pointer);
    assert_eq!(
        body.payload().as_slice(),
        block
            .canonical_resultless_proposal()
            .expect("valid fixture proposal projection")
            .encode_wire()
            .unwrap()
    );
    assert!(body.admitted_to(&budget));
    drop(body);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn absence_foreign_pool_and_corrupt_storage_are_separate_outcomes() {
    let (block, source, crypto, root_scope) = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let mut absent = FixtureRead::new(
        source.clone(),
        None,
        budget.clone(),
        crypto.clone(),
        root_scope,
    );
    assert!(matches!(
        absent.poll(&AllocationBudget::new(1 << 25)),
        Err(BodyReadError::ForeignBudget)
    ));
    assert!(matches!(absent.poll(&budget), Ok(BodyReadPoll::Absent)));
    assert!(matches!(
        absent.poll(&budget),
        Err(BodyReadError::Completed)
    ));
    let corrupt = crate::block::reserve_block_for_tests()
        .initialize(block.as_ref().clone().with_commit_certificate(None));
    let mut read = FixtureRead::new(source, Some(corrupt), budget.clone(), crypto, root_scope);
    for _ in 0..2 {
        assert!(
            matches!(read.poll(&budget), Err(BodyReadError::Io(ref e)) if e.kind() == io::ErrorKind::InvalidData)
        );
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn requested_hash_cannot_be_replaced_by_the_stored_certificate() {
    let (block, source, crypto, root_scope) = fixture();
    let source = AvailabilitySource::new(
        source.instance(),
        source.height(),
        Hash32([0x91; 32]),
        source.config().clone(),
    )
    .unwrap();
    let budget = AllocationBudget::new(1 << 25);
    let mut read = FixtureRead::new(
        source.clone(),
        Some(block.clone()),
        budget.clone(),
        crypto,
        root_scope,
    );
    for _ in 0..2 {
        assert!(
            matches!(read.poll(&budget), Err(BodyReadError::Io(ref e)) if e.kind() == io::ErrorKind::InvalidData)
        );
        let Stage::Decoded(decoded) = &read.body().stage else {
            panic!("keep exact rejected artifact")
        };
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &decoded.source,
            &block
        ));
        assert_eq!(read.source(), &source);
    }
}

#[test]
fn canonical_but_invalid_author_signature_never_becomes_available_custody() {
    let (block, source, crypto, root_scope) = fixture();
    let old = block.commit_certificate().unwrap();
    let original: AvailabilityFrame = norito::decode_canonical(old.availability()).unwrap();
    let mut table = original.as_slice().to_vec();
    let last = table.len() - 1;
    table[last] ^= 1;
    let table = AvailabilityFrame::from_untrusted(table).unwrap();
    let certificate = CommitCertificate::from_untrusted_parts(
        old.consensus_header().to_vec(),
        old.commit_qc().to_vec(),
        old.result_preimage().to_vec(),
        norito::encode_canonical(&table).unwrap(),
    );
    let changed = crate::block::reserve_block_for_tests().initialize(
        block
            .as_ref()
            .clone()
            .with_commit_certificate(Some(certificate)),
    );
    let budget = AllocationBudget::new(1 << 25);
    let mut read = FixtureRead::new(
        source,
        Some(changed),
        budget.clone(),
        crypto.clone(),
        root_scope,
    );
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("canonical untrusted input only")
    };
    let (_, error) = restoration
        .complete(&budget, &*crypto)
        .expect_err("actual signature rejection");
    assert!(!error.is_local_refusal());
}

#[test]
fn stored_result_decode_refusal_retains_original_decoded_owners_and_retries() {
    use iroha_data_model::sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES;

    let (block, source, crypto, root_scope) = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(block.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("original decoded certificate"));
    let table = decoded.availability.as_slice().as_ptr();
    let bitmap = decoded.commit_qc.signers.as_bytes().as_ptr();
    let mut read = StoredBodyRead::from_decoded(
        source.clone(),
        decoded,
        budget.clone(),
        crypto.clone(),
        root_scope,
    );
    let retained = budget.reserved_bytes();
    for _ in 0..2 {
        let outcome = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(96, MAX_RESULT_PREIMAGE_BYTES, usize::MAX, 0, 32),
            || read.poll(&budget),
        );
        let Err(BodyReadError::Deferred(reason)) = outcome else {
            panic!("result decode must refuse locally before projection");
        };
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(
            reason.allocation_refusal().is_none(),
            "Norito scopes do not invent a pool"
        );
        let Stage::Decoded(decoded) = &read.stage else {
            panic!("retain the same original decoded source");
        };
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &decoded.source,
            &block
        ));
        assert_eq!(decoded.availability.as_slice().as_ptr(), table);
        assert_eq!(decoded.commit_qc.signers.as_bytes().as_ptr(), bitmap);
        assert_eq!(read.source(), &source);
        assert_eq!(budget.reserved_bytes(), retained);
    }
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("retry the original input after local decode funding is available");
    };
    let body = restoration
        .complete(&budget, &*crypto)
        .unwrap_or_else(|_| panic!("the genuine signed body still verifies"));
    assert_eq!(body.availability().as_slice().as_ptr(), table);
    assert_eq!(body.source(), &source);
    assert!(body.admitted_to(&budget));
    drop((body, read));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn malformed_result_preimage_remains_terminal_storage_corruption() {
    use iroha_data_model::sumeragi_finality::{
        CertifiedResultError, CommitmentError,
        certified_result::{FinalityHeaderError, X_LEN},
    };

    let (block, _, _, root_scope) = fixture();
    super::super::execution::validate(&block, root_scope).unwrap();
    let original = block.commit_certificate().unwrap();
    // Preserve the original malformed body control and independently reject the new fixed X
    // prefix. Both are terminal corruption; neither may become a local resource refusal.
    for offset in [0, X_LEN] {
        let mut preimage = original.result_preimage().to_vec();
        preimage[offset] ^= 0xff;
        let certificate = CommitCertificate::from_untrusted_parts(
            original.consensus_header().to_vec(),
            original.commit_qc().to_vec(),
            preimage,
            original.availability().to_vec(),
        );
        let changed = block
            .as_ref()
            .clone()
            .with_commit_certificate(Some(certificate));
        let Attempt::Rejected(error) =
            super::super::execution::validate(&changed, root_scope).unwrap_err()
        else {
            panic!("malformed result must remain terminal");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let cause = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<CertifiedResultError>());
        if offset == 0 {
            assert!(matches!(
                cause,
                Some(CertifiedResultError::Header(FinalityHeaderError::X1))
            ));
        } else {
            assert!(matches!(
                cause,
                Some(CertifiedResultError::Body(CommitmentError::Encoding(_)))
            ));
        }
    }
}

#[test]
fn stored_certificate_allocator_refusal_keeps_original_read_and_retries() {
    use crate::test_allocations::refuse_one_layout_during;
    let (block, source, crypto, root_scope) = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let mut read = FixtureRead::new(
        source.clone(),
        Some(Clone::clone(&block)),
        budget.clone(),
        crypto.clone(),
        root_scope,
    );
    let (result, refused) =
        refuse_one_layout_during(std::alloc::Layout::array::<u8>(8).unwrap(), || {
            read.poll(&budget)
        });
    assert!(
        refused,
        "the real canonical bitmap decoder must reach the physical allocator"
    );
    let BodyReadError::Deferred(reason) =
        result.err().expect("physical decoder allocation refuses")
    else {
        panic!("physical allocation failure must remain an operational refusal");
    };
    assert_eq!(
        reason.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(
        reason.allocation_refusal().is_none(),
        "physical failure cannot invent pool custody"
    );
    let job = read
        .certificate
        .as_ref()
        .expect("same original certificate read");
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &block
    ));
    assert_eq!(read.source(), &source);
    assert_eq!(budget.reserved_bytes(), 0);
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("original read resumes");
    };
    let body = restoration
        .complete(&budget, &*crypto)
        .unwrap_or_else(|_| panic!("real source, signatures and complete codeword verify"));
    assert_eq!(body.source(), &source);
    drop(body);
    assert_eq!(budget.reserved_bytes(), 0);
}

/// Storage stage of the resource contract (`specs/zk_resource_contract.json`,
/// `block.max_block_bytes`): the stored-body projection is bounded by the committed payload
/// limit of the independently authenticated height. A stored proposal of exactly the limit is
/// restored; under a limit one byte smaller the read ends as storage corruption on every
/// attempt and reserves nothing, so no oversize body is rebuilt from disk.
#[test]
fn stored_body_projection_accepts_the_payload_limit_and_refuses_one_over() {
    let (block, source, crypto, root_scope) = fixture();
    let payload_len = block.resultless_proposal_wire_len().unwrap();
    assert!(payload_len > 0);
    let with_limit = |max_block_bytes: usize| {
        let mut config = source.config().clone();
        config.params.max_block_bytes = u32::try_from(max_block_bytes).unwrap();
        AvailabilitySource::new(
            source.instance(),
            source.height(),
            source.block_hash(),
            config,
        )
        .unwrap()
    };

    // Exactly the committed limit.
    let budget = AllocationBudget::new(1 << 25);
    let exact = with_limit(payload_len);
    let mut read = FixtureRead::new(
        exact.clone(),
        Some(block.clone()),
        budget.clone(),
        crypto.clone(),
        root_scope,
    );
    let BodyReadPoll::Ready(restoration) = read.poll(&budget).unwrap() else {
        panic!("a stored proposal of exactly the payload limit is restored");
    };
    assert_eq!(restoration.source(), &exact);
    drop((restoration, read));
    assert_eq!(budget.reserved_bytes(), 0);

    // One byte over the committed limit.
    let budget = AllocationBudget::new(1 << 25);
    let mut read = FixtureRead::new(
        with_limit(payload_len - 1),
        Some(block.clone()),
        budget.clone(),
        crypto,
        root_scope,
    );
    for _ in 0..2 {
        assert!(
            matches!(
                read.poll(&budget),
                Err(BodyReadError::Io(ref error)) if error.kind() == io::ErrorKind::InvalidData
            ),
            "one byte over the payload limit is a deterministic storage refusal"
        );
        let Stage::Projecting(job) = &read.body().stage else {
            panic!("the refused projection keeps its original decoded source");
        };
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &job.source().source,
            &block
        ));
    }
    drop(read);
    assert_eq!(budget.reserved_bytes(), 0);
}
