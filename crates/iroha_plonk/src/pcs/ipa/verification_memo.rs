//! Bounded, process-local memos of completed public verification work for one
//! immutable parameter owner.
//!
//! Each [`PinnedParams`] owner keeps two memos, shared by its clones and never by
//! independently derived or decoded owners:
//!
//! - **Folded generators.** `<s(u), g[0..2^k)>` keyed by the exact canonical
//!   challenge bytes `u` (`k = u.len()`). Only this crate's deciding operations
//!   insert, after the complete-kernel MSM finished and the decision accepted:
//!   [`PinnedParams::decide_folded_generator_cancellable`] (behind every
//!   generator-claim and accumulator decide) and production full verification.
//!   A lookup returns that exact public point; the comparison with a claimed `G`
//!   still runs on every call, so a false claim with the same challenges is still
//!   rejected and a correction still obtains the true point.
//! - **Successful full verifications.** A full SHA-256 over a domain tag, the
//!   curve, `k`, the descriptor digest and profile, the key's `transcript_repr`
//!   and the SHA-256 of its bytes, every length-framed instance value and the
//!   exact proof bytes. Only production `verify_full` inserts, after it returned
//!   `Ok`; it still runs every structural check and its cancellation checkpoint
//!   on a hit.
//!
//! Rejections, undecidable claims and cancelled or failed computations are never
//! inserted. Prover-side MSMs, batch decisions and caller-supplied points, digests
//! or flags cannot populate either memo: there is no insert or seed API. Entries
//! are SHA-256 digests, exact challenge bytes and the folded generators derived
//! from them. A verifier that fully verifies a proof the wallet keeps private (a
//! retained Q checkpoint) on a shared owner can therefore retain that proof's
//! transcript challenges and folded generator; no proof body, witness or private
//! fold tape is stored. Entries are bounded, process-local verification data:
//! never serialized, persisted or exposed, and they confer no authority beyond
//! the exact check they memoize. Locks
//! are never held while hashing or computing; a poisoned lock is ignored, the work
//! is recomputed and nothing is inserted. Both memos are bounded with
//! least-recently-used eviction.

use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use ff::{Field, PrimeField};
use iroha_pasta::{
    CancellationToken, PastaCurve,
    msm::{MemoryBudget, SharedMemoryBudget},
};

use super::{IpaError, PinnedParams, commit::msm_complete_cancellable, fold_scalars};

// A Receive fold restores about a hundred distinct claims per curve and verifies
// a few dozen distinct proofs; both bounds keep that working set resident.
const GENERATOR_ENTRIES: usize = 256;
const PROOF_ENTRIES: usize = 256;

/// Least-recently-used bounded map.
struct Lru<K: Ord + Clone, V: Copy> {
    entries: BTreeMap<K, (V, u64)>,
    recency: BTreeMap<u64, K>,
    tick: u64,
    capacity: usize,
}

impl<K: Ord + Clone, V: Copy> Lru<K, V> {
    const fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            recency: BTreeMap::new(),
            tick: 0,
            capacity,
        }
    }

    fn get<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let Self {
            entries,
            recency,
            tick,
            ..
        } = self;
        let (value, used) = entries.get_mut(key)?;
        *tick += 1;
        if let Some(owned) = recency.remove(used) {
            recency.insert(*tick, owned);
        }
        *used = *tick;
        Some(*value)
    }

    fn insert(&mut self, key: K, value: V) {
        if self.entries.contains_key(&key) {
            // A concurrent miss computed the same exact value; keep the first.
            return;
        }
        if self.entries.len() >= self.capacity
            && let Some((_, oldest)) = self.recency.pop_first()
        {
            self.entries.remove(&oldest);
        }
        self.tick += 1;
        self.entries.insert(key.clone(), (value, self.tick));
        self.recency.insert(self.tick, key);
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The memos of one parameter owner (see the module documentation).
pub(super) struct VerificationMemo<C: PastaCurve> {
    generators: Lru<Arc<[u8]>, C::AffineExt>,
    proofs: Lru<[u8; 32], ()>,
}

impl<C: PastaCurve> Default for VerificationMemo<C> {
    fn default() -> Self {
        Self {
            generators: Lru::new(GENERATOR_ENTRIES),
            proofs: Lru::new(PROOF_ENTRIES),
        }
    }
}

// Entries are runtime state, not parameter identity, and challenge keys may come from privately
// retained proofs: print sizes only.
impl<C: PastaCurve> fmt::Debug for VerificationMemo<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerificationMemo")
            .field("generators", &self.generators.len())
            .field("proofs", &self.proofs.len())
            .finish()
    }
}

pub(super) type SharedVerificationMemo<C> = Arc<Mutex<VerificationMemo<C>>>;

/// The exact canonical challenge bytes that key a folded generator: `u8(k)` and
/// each 32-byte challenge in order.
fn generator_key<F: PrimeField>(challenges: &[F]) -> Arc<[u8]> {
    let mut key = Vec::with_capacity(1 + 32 * challenges.len());
    // `require_k` bounded k by MAX_K (28) before any key is built.
    key.push(u8::try_from(challenges.len()).unwrap_or(u8::MAX));
    for challenge in challenges {
        key.extend_from_slice(challenge.to_repr().as_ref());
    }
    key.into()
}

/// A folded generator together with the exact key it was computed or found under.
pub(super) struct FoldedGenerator<C: PastaCurve> {
    key: Arc<[u8]>,
    point: C::AffineExt,
}

impl<C: PastaCurve> FoldedGenerator<C> {
    pub(super) const fn point(&self) -> &C::AffineExt {
        &self.point
    }
}

impl<C: PastaCurve> PinnedParams<C> {
    /// `<s(u), g[0..2^k)>` for `k = u.len()`, from this owner's memo or computed
    /// now with the complete kernel. Never inserts.
    pub(super) fn folded_generator_entry_cancellable(
        &self,
        challenges: &[C::ScalarExt],
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<FoldedGenerator<C>, IpaError> {
        CancellationToken::checkpoint(cancellation)?;
        let k = u32::try_from(challenges.len()).unwrap_or(u32::MAX);
        self.require_k(k)?;
        let key = generator_key(challenges);
        let remembered = self
            .verification_memo
            .lock()
            .ok()
            .and_then(|mut memo| memo.generators.get(&*key));
        if let Some(point) = remembered {
            CancellationToken::checkpoint(cancellation)?;
            crate::verification_counters::record_reused_generator();
            return Ok(FoldedGenerator { key, point });
        }
        let s = fold_scalars(challenges, C::ScalarExt::ONE);
        let g = &self.params().g()[..s.len()];
        crate::verification_counters::record_generator_msm(g.len());
        let point = msm_complete_cancellable::<C>(
            &s,
            g,
            budget,
            &SharedMemoryBudget::process_default(),
            cancellation,
        )?
        .to_affine();
        CancellationToken::checkpoint(cancellation)?;
        Ok(FoldedGenerator { key, point })
    }

    /// Remember a folded generator after the deciding operation that obtained it accepted.
    pub(super) fn remember_folded_generator(&self, generator: FoldedGenerator<C>) {
        if let Ok(mut memo) = self.verification_memo.lock() {
            memo.generators.insert(generator.key, generator.point);
        }
    }

    /// The folded generator `<s(u), g[0..2^k)>` of the exact challenges `u`
    /// (`k = u.len()`), for corrections and pinned constants.
    ///
    /// The value comes from this owner's memo of generators that an earlier
    /// decide or full verification accepted, or is computed now with the complete
    /// kernel. This never inserts and never decides anything.
    ///
    /// # Errors
    /// [`IpaError::ParamsTooSmall`] or [`IpaError::Cancelled`].
    pub fn folded_generator_cancellable(
        &self,
        challenges: &[C::ScalarExt],
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<C::AffineExt, IpaError> {
        Ok(self
            .folded_generator_entry_cancellable(challenges, budget, cancellation)?
            .point)
    }

    /// Decides `claimed == <s(u), g[0..2^k)>` for the exact challenges `u`
    /// (`k = u.len()`) with complete curve arithmetic.
    ///
    /// The comparison runs on every call. The point is computed by the complete
    /// kernel unless an earlier accepted decision of the same challenges on this
    /// owner retained it; only an accepting call retains it.
    ///
    /// # Errors
    /// [`IpaError::OpeningFailed`] for a false claim, [`IpaError::ParamsTooSmall`]
    /// or [`IpaError::Cancelled`].
    pub fn decide_folded_generator_cancellable(
        &self,
        challenges: &[C::ScalarExt],
        claimed: &C::AffineExt,
        budget: MemoryBudget,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), IpaError> {
        let generator =
            self.folded_generator_entry_cancellable(challenges, budget, cancellation)?;
        if generator.point != *claimed {
            return Err(IpaError::OpeningFailed);
        }
        self.remember_folded_generator(generator);
        Ok(())
    }

    /// Whether production full verification already accepted the exact inputs
    /// behind `key` on this owner.
    pub(crate) fn remembers_verified_proof(&self, key: &[u8; 32]) -> bool {
        self.verification_memo
            .lock()
            .ok()
            .and_then(|mut memo| memo.proofs.get(key))
            .is_some()
    }

    /// Remember that production full verification accepted the exact inputs behind `key`.
    pub(crate) fn remember_verified_proof(&self, key: [u8; 32]) {
        if let Ok(mut memo) = self.verification_memo.lock() {
            memo.proofs.insert(key, ());
        }
    }

    #[cfg(test)]
    pub(crate) fn verification_memo_sizes(&self) -> (usize, usize) {
        self.verification_memo
            .lock()
            .map(|memo| (memo.generators.len(), memo.proofs.len()))
            .unwrap_or((0, 0))
    }

    #[cfg(test)]
    pub(crate) fn poison_verification_memo(&self) {
        let memo = Arc::clone(&self.verification_memo);
        let _ = std::thread::spawn(move || {
            let _guard = memo.lock();
            panic!("poison the verification memo");
        })
        .join();
    }

    #[cfg(test)]
    pub(crate) fn shares_verification_memo(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.verification_memo, &other.verification_memo)
    }
}

#[cfg(test)]
mod tests;
