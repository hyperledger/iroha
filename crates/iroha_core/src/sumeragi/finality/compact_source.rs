//! Bounded acquisition of one original Commit certificate, without finality authority.

mod fields;

use std::{num::NonZeroU64, time::Instant};

use iroha_allocation::{AllocationBudget, AllocationReservation};
use iroha_data_model::sumeragi_finality::{
    FinalityError, MAX_COMMIT_CERTIFICATE_BYTES_V1, MAX_FINALITY_BLOCK_BYTES,
    SumeragiCommitCertificateV1,
};

use super::ProofError;
use crate::{state::StateReadOnly, sumeragi::certified_chain::ChainReadError};

/// Why one bounded original certificate could not be acquired.
#[derive(Debug, thiserror::Error)]
pub enum NativeCommitCertificateReadErrorV1 {
    /// The monotonic acquisition deadline expired.
    #[error("native Commit certificate acquisition deadline expired")]
    Deadline,
    /// Genesis has no Commit certificate, or the height is outside this State view.
    #[error("native Commit certificate height is outside the non-genesis State view")]
    Height,
    /// Original durable source acquisition or canonical decoding refused.
    #[error(transparent)]
    Source(#[from] ProofError),
    /// The original frame or selected canonical fields are malformed.
    #[error("native Commit certificate frame differs: {0}")]
    Frame(#[from] norito::Error),
    /// The original certificate is absent or its finite component shape differs.
    #[error("native finality source shape differs: {0}")]
    Shape(FinalityError),
    /// The original allocation pool or an actual allocation refused the copy.
    #[error("native Commit certificate allocation unavailable")]
    Allocation,
}

type Error = NativeCommitCertificateReadErrorV1;
type Result<T> = std::result::Result<T, Error>;

/// Original certificate DATA retaining the charge for its response allocations.
///
/// This is neither a verified block nor a current-state capability. The caller must
/// authenticate it with a genesis-rooted `SumeragiCommitVerifierV1` before using any
/// claimed height, epoch, roster or result as authority. The source State view pins
/// the durable frame, but does not replace independent certificate verification.
pub struct NativeCommitCertificateDataV1 {
    // Reclaim the copied vectors before refunding their original reservation.
    certificate: SumeragiCommitCertificateV1,
    charge: AllocationReservation,
}

impl NativeCommitCertificateDataV1 {
    /// Borrow the acquired DATA while its response allocation charge remains held.
    #[must_use]
    pub fn certificate(&self) -> &SumeragiCommitCertificateV1 {
        &self.certificate
    }

    /// Move the same certificate and charge into a response assembly owner.
    ///
    /// Retain the reservation until both the certificate and its encoded response
    /// have been released. Moving these values does not confer finality authority.
    #[must_use]
    pub fn into_parts(self) -> (SumeragiCommitCertificateV1, AllocationReservation) {
        (self.certificate, self.charge)
    }
}

// Preserve the existing physical-copy Allocation category while classifying original
// metadata/codec refusal before mapping a deterministic unavailable source.
fn storage_error(height: NonZeroU64, error: crate::kura::Error) -> Error {
    if matches!(&error, crate::kura::Error::NativeFrameAllocation(_)) {
        return Error::Allocation;
    }
    Error::Source(
        crate::execution_attempt::kura_read_attempt_error(error, |_| ChainReadError::NotInView {
            height: height.get(),
        })
        .into(),
    )
}

/// Read one State-pinned durable native frame and copy its original certificate.
///
/// No historical prefix is traversed and no quorum, execution, epoch or current
/// authority is granted. The caller must independently verify returned DATA. The
/// sole canonical record walks borrow the original frame's inline header and
/// certificate byte leaves; transactions, execution outputs and availability
/// remain opaque and are not decoded or independently validated by this reader.
/// One exact wire allocation and a fixed certificate-sized parser allowance are
/// charged, without a decoded body graph. The
/// returned reservation conservatively covers twice the copied
/// component bytes plus certificate shell, preserving the response/encoding budget.
/// These requested-allocation bounds are not RSS measurements.
///
/// # Errors
/// Refuses genesis/out-of-view heights, expired deadlines, unavailable or changed
/// original frames, malformed selected fields, certificate shape and allocation
/// failures. No cached decoded body or imported checkpoint substitutes for a read.
pub fn read_commit_certificate(
    view: &impl StateReadOnly,
    height: NonZeroU64,
    budget: &AllocationBudget,
    deadline: Instant,
) -> Result<NativeCommitCertificateDataV1> {
    check_deadline(deadline)?;
    let index = usize::try_from(height.get()).map_err(|_| Error::Height)?;
    if index < 2 || index > view.block_hashes().len() {
        return Err(Error::Height);
    }
    let unavailable = || {
        Error::Source(
            ChainReadError::NotInView {
                height: height.get(),
            }
            .into(),
        )
    };
    let expected = *view.block_hashes().get(index - 1).ok_or_else(unavailable)?;
    let source = view
        .kura()
        .native_frame_read(height.get(), expected)
        .map_err(|error| storage_error(height, error))?
        .ok_or_else(unavailable)?;
    let extent = usize::try_from(source.wire_len()).map_err(|_| unavailable())?;
    if extent == 0 || extent > MAX_FINALITY_BLOCK_BYTES {
        return Err(unavailable());
    }
    check_deadline(deadline)?;
    let bytes = source
        .read_original(source.wire_len(), budget)
        .map_err(|error| storage_error(height, error))?
        .ok_or_else(unavailable)?;
    check_deadline(deadline)?;
    let _selector_charge = budget
        .try_reserve_bytes(fields::SCRATCH_BYTES)
        .map_err(|_| Error::Allocation)?;
    let selected = fields::select(bytes.as_slice())?;
    if selected.header.height() != height || selected.header.hash() != expected {
        return Err(unavailable());
    }
    let [header, qc, result] = selected.components;
    let component_bytes = header
        .len()
        .checked_add(qc.len())
        .and_then(|length| length.checked_add(result.len()))
        .ok_or(Error::Allocation)?;
    if component_bytes > MAX_COMMIT_CERTIFICATE_BYTES_V1 {
        return Err(Error::Shape(FinalityError(
            "native certificate exceeds its finite bound".into(),
        )));
    }
    let response_bytes = component_bytes
        .checked_add(std::mem::size_of::<SumeragiCommitCertificateV1>())
        .and_then(|length| length.checked_mul(2))
        .ok_or(Error::Allocation)?;
    let charge = budget
        .try_reserve_bytes(response_bytes)
        .map_err(|_| Error::Allocation)?;
    let certificate = SumeragiCommitCertificateV1 {
        consensus_header: copy_component(header, deadline)?,
        commit_qc: copy_component(qc, deadline)?,
        result_preimage: copy_component(result, deadline)?,
    };
    certificate.validate_shape().map_err(Error::Shape)?;
    check_deadline(deadline)?;
    Ok(NativeCommitCertificateDataV1 {
        certificate,
        charge,
    })
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}

fn copy_component(bytes: &[u8], deadline: Instant) -> Result<Vec<u8>> {
    check_deadline(deadline)?;
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::Allocation)?;
    for chunk in bytes.chunks(64 * 1024) {
        check_deadline(deadline)?;
        copied.extend_from_slice(chunk);
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, time::Duration};

    use iroha_data_model::{
        block::decode_framed_signed_block,
        sumeragi_finality::{SumeragiCommitVerifierV1, SumeragiFinalityVerifier},
    };

    use super::*;
    use crate::{
        state::World,
        sumeragi::{
            finality::build_proof,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };

    // Finish the genuine native fixture before the independent assertion frame.
    #[inline(never)]
    fn with_chain(height: u64, check: fn(&CertifiedTestChain)) {
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
            .expect("signed genesis");
        while chain.height() < height {
            chain.commit(Vec::new());
        }
        check(&chain);
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn verifier(view: &impl StateReadOnly) -> SumeragiCommitVerifierV1 {
        let genesis = build_proof(view, 1).unwrap();
        let signed = decode_framed_signed_block(&genesis.block_wire).unwrap();
        let native =
            SumeragiFinalityVerifier::new(&signed, view.chain_id().as_str(), genesis.committee)
                .unwrap();
        SumeragiCommitVerifierV1::new(&native).unwrap()
    }

    #[test]
    fn compact_source_preserves_original_cumulative_metadata_refusal_before_body_io() {
        with_chain(2, check_metadata_refusal);
    }

    #[inline(never)]
    fn check_metadata_refusal(chain: &CertifiedTestChain) {
        use ivm::error::ExecutionDeferral;
        let expected = chain.committed(2).block_hash();
        let bound = |allocation| {
            norito::DecodeLimits::new(1_000_000, 48 * 1024 * 1024, 1_000_000, allocation, 64)
        };
        let probe = norito::core::DecodeBudgetContext::new(bound(48 * 1024 * 1024));
        probe.with(|| {
            chain
                .kura()
                .native_frame_read(2, expected)
                .unwrap()
                .unwrap();
        });
        let marker_work = probe.consumed_allocated_bytes();
        assert!(marker_work > 0);
        let budget = AllocationBudget::new(64 << 20);
        // Primed: preflight itself refuses. Unprimed: preflight spends the complete
        // allowance, then read_original's real repeated marker refuses before bytes.
        for primed in [true, false] {
            let context = norito::core::DecodeBudgetContext::new(bound(
                usize::try_from(marker_work).unwrap(),
            ));
            if primed {
                context.with(|| {
                    chain
                        .kura()
                        .native_frame_read(2, expected)
                        .unwrap()
                        .unwrap();
                });
            }
            chain.kura().reset_canonical_query_reads_for_test();
            for _ in 0..2 {
                let result = context.with(|| {
                    read_commit_certificate(
                        &chain.state().view(),
                        NonZeroU64::new(2).unwrap(),
                        &budget,
                        deadline(),
                    )
                });
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!(
                        "exhausted original marker scope cannot complete certificate acquisition"
                    ),
                };
                let Error::Source(ProofError::Deferred(ref original)) = error else {
                    panic!(
                        "original compact certificate metadata refusal must remain local before body acquisition: {error:?}"
                    );
                };
                assert_eq!(original.reason(), ExecutionDeferral::ActiveMemoryCapacity);
                assert!(original.allocation_refusal().is_none());
                assert_eq!(context.consumed_allocated_bytes(), marker_work);
                assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
                assert_eq!(budget.reserved_bytes(), 0);
            }
        }
        let data = read_commit_certificate(
            &chain.state().view(),
            NonZeroU64::new(2).unwrap(),
            &budget,
            deadline(),
        )
        .unwrap();
        assert_eq!(
            data.certificate().commit_qc,
            chain
                .committed(2)
                .block()
                .commit_certificate()
                .unwrap()
                .commit_qc()
        );
        assert!(budget.reserved_bytes() > 0);
        drop(data);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn compact_source_preserves_original_certificate_and_response_charge() {
        with_chain(2, check_original);
    }

    #[test]
    fn compact_source_field_walk_rejects_noncanonical_original_framing() {
        with_chain(2, check_framing);
    }

    #[inline(never)]
    fn check_framing(chain: &CertifiedTestChain) {
        let block = chain.committed(2);
        let wire = block.block().encode_wire().unwrap();
        let selected = fields::select(&wire).unwrap();
        assert_eq!(selected.header.hash(), block.block().hash());
        assert_eq!(
            selected.components[0],
            block
                .block()
                .commit_certificate()
                .unwrap()
                .consensus_header()
        );
        for component in selected.components {
            assert!(component.as_ptr().addr() >= wire.as_ptr().addr());
            assert!(
                component.as_ptr().addr() + component.len() <= wire.as_ptr().addr() + wire.len()
            );
        }
        let mut version = wire.clone();
        version[0] = 2;
        assert!(fields::select(&version).is_err());
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(fields::select(&trailing).is_err());
        let mut checksum = wire.clone();
        *checksum.last_mut().unwrap() ^= 1;
        assert!(fields::select(&checksum).is_err());
        let mut layout = wire.clone();
        layout[norito::core::Header::SIZE] ^= 1;
        assert!(fields::select(&layout).is_err());
        assert!(fields::select(&wire[1..]).is_err());
    }

    #[inline(never)]
    fn check_original(chain: &CertifiedTestChain) {
        let view = chain.state().view();
        let original = chain.committed(2);
        let raw = original.block().commit_certificate().unwrap();
        let budget = AllocationBudget::new(64 << 20);
        let data = read_commit_certificate(&view, NonZeroU64::new(2).unwrap(), &budget, deadline())
            .unwrap();
        assert_eq!(data.certificate().consensus_header, raw.consensus_header());
        assert_eq!(data.certificate().commit_qc, raw.commit_qc());
        assert_eq!(data.certificate().result_preimage, raw.result_preimage());
        let expected_charge = 2
            * (raw.consensus_header().len()
                + raw.commit_qc().len()
                + raw.result_preimage().len()
                + std::mem::size_of::<SumeragiCommitCertificateV1>());
        assert_eq!(budget.reserved_bytes(), expected_charge);
        assert_eq!(
            verifier(&view).verify(data.certificate()).unwrap().height(),
            2
        );
        let (certificate, charge) = data.into_parts();
        assert!(charge.belongs_to(&budget));
        assert_eq!(charge.remaining_bytes(), expected_charge);
        assert_eq!(budget.reserved_bytes(), expected_charge);
        drop(certificate);
        assert_eq!(budget.reserved_bytes(), expected_charge);
        drop(charge);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn compact_source_refuses_deadline_budget_and_invalid_heights() {
        with_chain(2, check_refusals);
    }

    #[inline(never)]
    fn check_refusals(chain: &CertifiedTestChain) {
        let view = chain.state().view();
        let budget = AllocationBudget::new(64 << 20);
        for height in [1, 3, u64::MAX] {
            assert!(matches!(
                read_commit_certificate(
                    &view,
                    NonZeroU64::new(height).unwrap(),
                    &budget,
                    deadline()
                ),
                Err(Error::Height)
            ));
        }
        assert!(matches!(
            read_commit_certificate(&view, NonZeroU64::new(2).unwrap(), &budget, Instant::now()),
            Err(Error::Deadline)
        ));
        let empty = AllocationBudget::new(0);
        assert!(matches!(
            read_commit_certificate(&view, NonZeroU64::new(2).unwrap(), &empty, deadline()),
            Err(Error::Allocation)
        ));
        assert_eq!(empty.reserved_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), 0);
        let wire_len = chain.committed(2).block().encode_wire().unwrap().len();
        let scratch_short = AllocationBudget::new(wire_len + fields::SCRATCH_BYTES - 1);
        assert!(matches!(
            read_commit_certificate(
                &view,
                NonZeroU64::new(2).unwrap(),
                &scratch_short,
                deadline()
            ),
            Err(Error::Allocation)
        ));
        assert_eq!(scratch_short.reserved_bytes(), 0);
        drop(
            read_commit_certificate(&view, NonZeroU64::new(2).unwrap(), &budget, deadline())
                .unwrap(),
        );
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn compact_source_never_substitutes_cached_body_for_corrupt_original() {
        with_chain(2, check_original_loss);
    }

    #[inline(never)]
    fn check_original_loss(chain: &CertifiedTestChain) {
        let view = chain.state().view();
        let budget = AllocationBudget::new(64 << 20);
        drop(
            read_commit_certificate(&view, NonZeroU64::new(2).unwrap(), &budget, deadline())
                .unwrap(),
        );
        chain
            .kura()
            .corrupt_native_frame_for_test(NonZeroUsize::new(2).unwrap());
        assert!(matches!(
            read_commit_certificate(&view, NonZeroU64::new(2).unwrap(), &budget, deadline()),
            Err(Error::Source(_) | Error::Frame(_))
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn compact_source_reads_selected_frame_without_replaying_ordinary_prefix() {
        with_chain(3, check_no_prefix);
    }

    #[test]
    fn compact_source_large_executed_block_fits_default_query_pool_without_body_decode() {
        use iroha_data_model::{Level, isi::Log};

        let config = TestChainConfig::new(World::new(), 1_000);
        let signer = config.genesis_key.clone();
        let mut chain = CertifiedTestChain::start(config).unwrap();
        let transactions = (0..8)
            .map(|index| {
                chain.sign(
                    &signer,
                    [
                        Log::new(Level::TRACE, format!("{index}:{}", "x".repeat(128 * 1024)))
                            .into(),
                    ],
                    2_000,
                )
            })
            .collect();
        assert_eq!(chain.commit_at(2_000, transactions), vec![true; 8]);
        check_large_frame(&chain);
    }

    #[inline(never)]
    fn check_large_frame(chain: &CertifiedTestChain) {
        let view = chain.state().view();
        let original = chain.committed(2);
        let wire = original.block().encode_wire().unwrap();
        assert!(wire.len() > 1 << 20);
        let budget = AllocationBudget::new(48_000_000);
        let receipt_source_charge = budget.try_reserve_bytes(12_000_000).unwrap();
        assert!(
            budget
                .try_reserve_bytes(
                    norito::canonical_decode_limits(wire.len()).max_total_allocated_bytes()
                )
                .is_err(),
            "the retired full-body decode would refuse this real block"
        );
        let data = read_commit_certificate(&view, NonZeroU64::new(2).unwrap(), &budget, deadline())
            .unwrap();
        assert_eq!(
            verifier(&view).verify(data.certificate()).unwrap().height(),
            2
        );
        drop(data);
        assert_eq!(budget.reserved_bytes(), 12_000_000);
        drop(receipt_source_charge);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[inline(never)]
    fn check_no_prefix(chain: &CertifiedTestChain) {
        let view = chain.state().view();
        let mut independent = verifier(&view);
        chain
            .kura()
            .corrupt_native_frame_for_test(NonZeroUsize::new(2).unwrap());
        let budget = AllocationBudget::new(64 << 20);
        let data = read_commit_certificate(&view, NonZeroU64::new(3).unwrap(), &budget, deadline())
            .unwrap();
        assert_eq!(independent.verify(data.certificate()).unwrap().height(), 3);
        drop(data);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
