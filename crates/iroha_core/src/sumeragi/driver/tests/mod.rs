//! Tests of the Sumeragi driver: the execution scheduler (O3, O4, apply sequencing against a
//! single-overlay executor), the kernel (O1, O2, O5, O7, bounded serving and held effects under
//! a failing disk), the §13.5 conformance runs of the production kernel inside the
//! `iroha_sumeragi` simulator (F9, F13, F14, F27, F29, F32, F37 and a 20 s write failure under
//! O-AGR, O-SIGN, O-PBS, O-LIVE, O-MEM with the driver's queues, plus the O2 kill at every write
//! completion and an O4 answer oracle), and threaded runs of the full driver over the fake
//! backends (O9 with two instances in one process, panicking backends, a stopped worker, a
//! serving flood, O10 after a committed parameter change), and the full driver over the
//! production file stores with injected `ENOSPC`/`EIO`.

pub(super) mod fakes;

mod conformance;
mod file_stores;
mod kernel;
mod sched;
mod sim_host;
mod threaded;

use iroha_sumeragi::{
    availability::AvailableBody,
    message::{BlockHeader, Qc, VoteKind},
    preimage::payload_hash,
    testing::FakeCrypto,
    types::{AggregateSignature, Bitmap, Hash32, SIGNATURE_LEN},
};

std::thread_local! {
    static TEST_BUDGET: iroha_allocation::AllocationBudget = iroha_allocation::AllocationBudget::new(1 << 28);
}
/// One original pool retained by all fixture workers of this test instance.
pub(super) fn test_budget() -> iroha_allocation::AllocationBudget {
    TEST_BUDGET.with(Clone::clone)
}
/// Prepay every bounded scheduler waiter before this test creates pressure.
pub(super) fn test_registrations() -> super::exec::ExecutionRegistrations {
    super::exec::ExecutionRegistrations::admit(&test_budget()).unwrap()
}
/// Admit an actual nonempty builder result under the fixture's original pool.
pub(super) fn payload(bytes: Vec<u8>) -> Option<iroha_sumeragi::availability::PayloadBytes> {
    if bytes.is_empty() {
        return None;
    }
    let mut payload = iroha_sumeragi::availability::PayloadBytes::from_untrusted(bytes).unwrap();
    payload.admit(&test_budget()).unwrap();
    Some(payload)
}
/// Author exact application bytes through the actual signed RS16 worker.
pub(super) fn block(
    height: u64,
    parent: Hash32,
    parent_result: Hash32,
    payload: Vec<u8>,
) -> AvailableBody {
    assert!(
        !payload.is_empty(),
        "available-body fixture needs actual nonempty work"
    );
    let validators = iroha_sumeragi::testing::FakeValidators::new(4, 7, None);
    let config = iroha_sumeragi::types::HeightConfig {
        epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
        committee: validators.committee.clone(),
        params: iroha_sumeragi::types::ChainParams::default(),
    };
    let header = BlockHeader {
        control_witness: iroha_sumeragi::types::ControlWitness::empty(),
        epoch: config.epoch.id,
        instance: Hash32([5; 32]),
        height,
        origin_view: 0,
        parent_hash: parent,
        parent_result,
        payload_hash: payload_hash(&validators.crypto, &payload),
        availability_digest: Hash32::ZERO,
        payload_len: u32::try_from(payload.len()).unwrap(),
        proposer: 0,
        skipped_leaders: Vec::new(),
    };
    iroha_sumeragi::testing::author_body(
        header,
        &payload,
        &config,
        &test_budget(),
        &validators.crypto,
        validators.signer(0),
    )
}

/// The block hash under the fake crypto.
pub(super) fn hash(block: &AvailableBody) -> Hash32 {
    block.hash(&FakeCrypto::new())
}

/// A `CommitQC` of `block` certifying `result` (no signers: only the driver reads it here).
pub(super) fn commit_qc(block: &AvailableBody, result: Hash32) -> Qc {
    Qc {
        epoch: block.header().epoch,
        kind: VoteKind::Commit,
        instance: block.header().instance,
        height: block.header().height,
        view: 0,
        block_hash: hash(block),
        result,
        signers: Bitmap::new(4),
        agg_sig: AggregateSignature([0; SIGNATURE_LEN]),
    }
}

/// Send original manifest followed by exact actual codec rows through the normal ingress.
pub(super) fn row_messages(body: &AvailableBody) -> Vec<iroha_sumeragi::message::WireMessage> {
    use iroha_sumeragi::message::{PayloadChunk, PayloadManifest, WireMessage};
    let shape = body
        .source()
        .config()
        .epoch
        .da_layout
        .shape(u64::from(body.header().payload_len))
        .unwrap();
    let encoded = iroha_primitives::erasure::rs16::compact::encode_funded(
        shape,
        body.payload().as_slice(),
        &test_budget(),
    )
    .unwrap();
    let mut messages = vec![WireMessage::PayloadManifest(PayloadManifest {
        header: body.header().clone(),
        availability: body.availability().clone(),
    })];
    for index in 0..shape.chunk_count() {
        messages.push(WireMessage::PayloadChunk(PayloadChunk {
            instance: body.header().instance,
            height: body.header().height,
            block_hash: hash(body),
            index: index as u32,
            bytes: iroha_sumeragi::availability::RowBytes::from_untrusted(
                encoded.codeword()[shape.chunk_range(index).unwrap()].to_vec(),
            )
            .unwrap(),
        }));
    }
    messages
}

/// Independent authenticated fixture authority for one expected body identity.
pub(super) fn source(
    height: u64,
    block_hash: Hash32,
) -> iroha_sumeragi::availability::AvailabilitySource {
    let validators = iroha_sumeragi::testing::FakeValidators::new(4, 7, None);
    iroha_sumeragi::availability::AvailabilitySource::new(
        Hash32([5; 32]),
        height,
        block_hash,
        iroha_sumeragi::types::HeightConfig {
            epoch: Box::new(iroha_sumeragi::testing::TEST_EPOCH),
            committee: validators.committee,
            params: iroha_sumeragi::types::ChainParams::default(),
        },
    )
    .unwrap()
}
