//! Exact unblinded partial MSMs, scoped to one immutable parameter owner.

use std::collections::{BTreeMap, VecDeque};

use ff::PrimeField;
use group::prime::PrimeCurveAffine;
use iroha_pasta::{
    CancellationToken, PastaCurve,
    msm::{MemoryBudget, MsmError, SharedMemoryBudget, msm_public_cancellable},
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use super::{DEFAULT_BLIND, PinnedParams};

const BLOCK_ROWS: usize = 1024;
const MAX_WAVE_BLOCKS: usize = 8;
// Bounded independently of catalogue size. Only digests and computed projective
// points persist; projective storage avoids an inversion for every partial MSM.
const MAX_BLOCKS: usize = 16_384;
const BLOCK_DOMAIN: &[u8] = b"iroha:pipa:public-lagrange-unblinded-block:v1\0";

type BlockResult<C> = Result<([u8; 32], C, bool), MsmError>;

#[derive(Debug)]
pub(super) struct PublicBlockCache<C: PastaCurve> {
    points: BTreeMap<[u8; 32], C>,
    order: VecDeque<[u8; 32]>,
}

impl<C: PastaCurve> Default for PublicBlockCache<C> {
    fn default() -> Self {
        Self {
            points: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl<C: PastaCurve> PublicBlockCache<C> {
    fn insert(&mut self, digest: [u8; 32], computed: C) {
        if self.points.contains_key(&digest) {
            return;
        }
        if self.points.len() == MAX_BLOCKS
            && let Some(oldest) = self.order.pop_front()
        {
            self.points.remove(&oldest);
        }
        self.points.insert(digest, computed);
        self.order.push_back(digest);
    }
}

// None denotes an actually all-zero native slice, whose unblinded contribution
// is the identity. No encoded artifact claim or expected point enters this key.
fn block_digest<F: PrimeField>(
    offset: usize,
    values: &[F],
    cancellation: Option<&CancellationToken>,
) -> Result<Option<[u8; 32]>, MsmError> {
    CancellationToken::checkpoint(cancellation)?;
    let mut zero = true;
    for chunk in values.chunks(256) {
        CancellationToken::checkpoint(cancellation)?;
        if chunk.iter().any(|value| !bool::from(value.is_zero())) {
            zero = false;
            break;
        }
    }
    CancellationToken::checkpoint(cancellation)?;
    if zero {
        return Ok(None);
    }
    let mut hash = Sha256::new();
    hash.update(BLOCK_DOMAIN);
    hash.update((offset as u64).to_le_bytes());
    hash.update((values.len() as u64).to_le_bytes());
    for (row, value) in values.iter().enumerate() {
        if row % 256 == 0 {
            CancellationToken::checkpoint(cancellation)?;
        }
        hash.update(value.to_repr());
    }
    CancellationToken::checkpoint(cancellation)?;
    Ok(Some(hash.finalize().into()))
}

/// Compute a complete column on a whole-column miss. The owner fixes both curve
/// and all generator bases. The caller alone retains the completed commitment.
pub(super) fn commit_column<C: PastaCurve>(
    owner: &PinnedParams<C>,
    values: &[C::ScalarExt],
    budget: MemoryBudget,
    shared: &SharedMemoryBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<C, MsmError> {
    CancellationToken::checkpoint(cancellation)?;
    let bases = owner.params.g_lagrange();
    if values.len() > bases.len() {
        return Err(MsmError::LengthMismatch(iroha_pasta::LengthMismatch {
            left: values.len(),
            right: bases.len(),
        }));
    }
    #[cfg(test)]
    let observer = crate::pcs::ipa::commit::test_observation::partial_observation();
    let mut sum = C::identity();
    for (wave_index, wave_values) in values.chunks(BLOCK_ROWS * MAX_WAVE_BLOCKS).enumerate() {
        // Retain only eight borrowed slices/points; no row buffers or unbounded
        // work list. Hash and look up exact native blocks in row-offset order.
        let mut work = Vec::with_capacity(MAX_WAVE_BLOCKS);
        for (index, block) in wave_values.chunks(BLOCK_ROWS).enumerate() {
            let offset = (wave_index * MAX_WAVE_BLOCKS + index) * BLOCK_ROWS;
            let Some(digest) = block_digest(offset, block, cancellation)? else {
                continue;
            };
            let cached = owner
                .public_columns
                .lock()
                .ok()
                .and_then(|cache| cache.blocks.points.get(&digest).copied());
            work.push((offset, digest, block, cached));
        }
        // Indexed collection joins every worker, including after an error. No
        // cache lock spans hashing, Rayon work or shared scratch admission.
        let completed: Vec<BlockResult<C>> = work
            .into_par_iter()
            .map(|(offset, digest, block, cached)| {
                CancellationToken::checkpoint(cancellation)?;
                if let Some(point) = cached {
                    return Ok((digest, point, false));
                }
                #[cfg(test)]
                crate::pcs::ipa::commit::test_observation::record_partial(observer.as_ref());
                let computed = msm_public_cancellable::<C>(
                    block,
                    &bases[offset..offset + block.len()],
                    budget,
                    shared,
                    cancellation,
                )?;
                CancellationToken::checkpoint(cancellation)?;
                Ok((digest, computed, true))
            })
            .collect();
        CancellationToken::checkpoint(cancellation)?;
        // Keep FIFO insertion and addition deterministic regardless of which
        // worker completed first. A failed wave never publishes a full column.
        for result in completed {
            let (digest, point, computed) = result?;
            CancellationToken::checkpoint(cancellation)?;
            if computed && let Ok(mut cache) = owner.public_columns.lock() {
                cache.blocks.insert(digest, point);
            }
            sum += point;
        }
    }
    // Partial entries are always unblinded. Add the column blind exactly once,
    // including the empty/all-zero column case, then check before returning.
    sum += owner.params.w().to_curve() * C::ScalarExt::from(DEFAULT_BLIND);
    CancellationToken::checkpoint(cancellation)?;
    Ok(sum)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod benchmark;
