//! Bounded memo of computed public source-column commitments for one parameter owner.
//!
//! Only the fixed Lagrange/default-blind commitment operation can populate this
//! private cache. Expected VK points, artifact digests and admission seals never
//! enter it. Immutable parameter ownership and the curve type bind the basis;
//! clones share that owner, independently admitted parameters do not. The cache
//! retains only column digests and computed points, never scalar tables.
//! Whole-column misses reuse bounded exact unblinded 1,024-row partial MSMs,
//! binding every scalar, offset and length to this same parameter owner.

use std::collections::{BTreeMap, VecDeque};

use ff::PrimeField;
use iroha_pasta::{
    CancellationToken, PastaCurve,
    msm::{MemoryBudget, MsmError, SharedMemoryBudget},
};
use sha2::{Digest, Sha256};

use super::{PinnedParams, commit::DEFAULT_BLIND};

mod blocks;

// The largest measured wallet parameter owner has 5,666 distinct public columns.
// Keep that working set resident without retaining scalar tables. FIFO eviction
// remains bounded for future catalogues or unrelated callers.
const MAX_COLUMNS: usize = 8192;
const COLUMN_DOMAIN: &[u8] = b"iroha:pipa:fixed-lagrange-defaultblind:v1\0";

/// FIFO eviction bounds retained public metadata independently of catalogue size.
#[derive(Debug)]
pub(super) struct PublicColumnCache<C: PastaCurve> {
    points: BTreeMap<[u8; 32], C::AffineExt>,
    order: VecDeque<[u8; 32]>,
    blocks: blocks::PublicBlockCache<C>,
}

impl<C: PastaCurve> Default for PublicColumnCache<C> {
    fn default() -> Self {
        Self {
            points: BTreeMap::new(),
            order: VecDeque::new(),
            blocks: blocks::PublicBlockCache::default(),
        }
    }
}

impl<C: PastaCurve> PublicColumnCache<C> {
    fn insert(&mut self, digest: [u8; 32], computed: C::AffineExt) {
        if self.points.contains_key(&digest) {
            return;
        }
        if self.points.len() == MAX_COLUMNS
            && let Some(oldest) = self.order.pop_front()
        {
            self.points.remove(&oldest);
        }
        self.points.insert(digest, computed);
        self.order.push_back(digest);
    }
}

/// Hash DATA inseparably borrowed from the exact immutable native scalar slice.
/// No original digest or expected commitment can construct this handle.
#[derive(Clone, Copy, Debug)]
pub struct HashedPublicColumn<'a, F: PrimeField> {
    values: &'a [F],
    digest: [u8; 32],
}

impl<'a, F: PrimeField> HashedPublicColumn<'a, F> {
    /// Hash every actual scalar and stream its same canonical bytes to a caller.
    /// The caller's stream cannot affect this independently framed column hash.
    pub(crate) fn with_canonical_sink(
        values: &'a [F],
        mut sink: impl FnMut(&[u8]),
        cancellation: Option<&CancellationToken>,
    ) -> Result<Self, MsmError> {
        CancellationToken::checkpoint(cancellation)?;
        let mut hash = Sha256::new();
        hash.update(COLUMN_DOMAIN);
        hash.update(DEFAULT_BLIND.to_le_bytes());
        hash.update((values.len() as u64).to_le_bytes());
        for (row, value) in values.iter().enumerate() {
            if row % 1024 == 0 {
                CancellationToken::checkpoint(cancellation)?;
            }
            let canonical = value.to_repr();
            hash.update(canonical.as_ref());
            sink(canonical.as_ref());
        }
        CancellationToken::checkpoint(cancellation)?;
        Ok(Self {
            values,
            digest: hash.finalize().into(),
        })
    }
}

#[cfg(test)]
fn column_digest<F: PrimeField>(
    values: &[F],
    cancellation: Option<&CancellationToken>,
) -> Result<[u8; 32], MsmError> {
    Ok(HashedPublicColumn::with_canonical_sink(values, |_| {}, cancellation)?.digest)
}

impl<C: PastaCurve> PinnedParams<C> {
    /// Compute a public source-column commitment, reusing an identical computation
    /// within this immutable parameter owner. No expected point is accepted.
    #[cfg(test)]
    pub(crate) fn commit_public_column_cancellable(
        &self,
        values: &[C::ScalarExt],
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C::AffineExt, MsmError> {
        CancellationToken::checkpoint(cancellation)?;
        let bases = self.params.g_lagrange();
        if values.len() > bases.len() {
            return Err(MsmError::LengthMismatch(iroha_pasta::LengthMismatch {
                left: values.len(),
                right: bases.len(),
            }));
        }
        let column = HashedPublicColumn::with_canonical_sink(values, |_| {}, cancellation)?;
        self.commit_hashed_public_column_cancellable(&column, budget, cancellation)
    }

    /// Commit the exact immutable slice whose canonical values made this handle.
    /// Expected VK points and declared original digests are never accepted.
    pub(crate) fn commit_hashed_public_column_cancellable(
        &self,
        column: &HashedPublicColumn<'_, C::ScalarExt>,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C::AffineExt, MsmError> {
        self.commit_hashed_with_shared_budget(
            column,
            budget,
            &SharedMemoryBudget::process_default(),
            cancellation,
        )
    }

    fn commit_hashed_with_shared_budget(
        &self,
        column: &HashedPublicColumn<'_, C::ScalarExt>,
        budget: MemoryBudget,
        shared: &SharedMemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C::AffineExt, MsmError> {
        CancellationToken::checkpoint(cancellation)?;
        let values = column.values;
        let bases = self.params.g_lagrange();
        if values.len() > bases.len() {
            return Err(MsmError::LengthMismatch(iroha_pasta::LengthMismatch {
                left: values.len(),
                right: bases.len(),
            }));
        }
        let digest = column.digest;
        let cached = self
            .public_columns
            .lock()
            .ok()
            .and_then(|cache| cache.points.get(&digest).copied());
        if let Some(point) = cached {
            CancellationToken::checkpoint(cancellation)?;
            return Ok(point);
        }
        // Never hold the cache lock during hashing or MSM. Concurrent misses may
        // compute the same point; either exact computation is safe to retain.
        #[cfg(test)]
        super::commit::test_observation::record();
        let computed =
            blocks::commit_column(self, values, budget, shared, cancellation)?.to_affine();
        CancellationToken::checkpoint(cancellation)?;
        if let Ok(mut cache) = self.public_columns.lock() {
            cache.insert(digest, computed);
        }
        // A poisoned cache is ignored and safely recomputed, never authority.
        CancellationToken::checkpoint(cancellation)?;
        Ok(computed)
    }
}

#[cfg(test)]
mod tests;
