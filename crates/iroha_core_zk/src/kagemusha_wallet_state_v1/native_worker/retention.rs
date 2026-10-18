//! Volatile fold state retained between the sub-proofs of one step (D6b).
//!
//! A sub-proof that publishes a checkpoint leaves the next sub-proof of its step what it already
//! derived and verified: the step's native inputs, the Q preparation in restore form with the
//! Q originals it restored, or the family session (D6a) with the A and W checkpoints it
//! restored. The next sub-proof resumes it only for the same `RetentionKeyV1`, computed from the
//! values the coordinator selected and re-chained in that turn, and only while the payloads it
//! holds are a byte-exact prefix of the durable checkpoint list. Any other value, or none, is
//! that call's cold path; a mismatch is never an error.
//!
//! No copy of a durable payload is held: the prefix rule compares SHA-256 identities. Nothing a
//! proof produced is held either: the checkpoint a sub-proof publishes is restored strictly from
//! its durable bytes by the next one, and a σ preparation from fresh coins is never held. Every
//! other value keeps the type it has during a call and is moved, never copied. The σ private
//! fold and the private folds of the restored Q originals stay in `PrivateFoldBytes`, which
//! clears on its last drop. The plain bytes are in-call types, freed but not cleared when the
//! state is dropped: the proof bytes the strict restores decoded into the restored Q originals
//! and A/W checkpoints, the originals and Q proofs inside the family session's verified
//! preparation, the σ proofs of the Q sources and of the σ preparation, the owner credential
//! (`AuthenticatedCredentialV1`) and the fold fields (`Fields`). The state is process-local and
//! grants nothing: every stage still imports its key with full custody checks, and every native
//! check runs.

use super::super::{FoldCustodyV1, ReleasedStep};
use super::inputs::Fields;
use super::stages::FamilyStateV1;
use super::*;
use crate::kagemusha_wallet_preparation_v1::AuthenticatedCredentialV1;
use iroha_data_model::kagemusha::{KagemushaWalletFoldRecordV1, KagemushaWalletLineagePublicV1};

/// The durable inputs one sub-proof's derived state belongs to. Every field is read in the
/// same turn from what the coordinator selected: the installation, the released step, its
/// predecessor Ω and the fold custody view. Nothing is re-derived from the retained state.
///
/// The issued-Request, direct-anchor and finality-epoch index roots are deliberately absent.
/// Every lookup the skipped replay makes through them is keyed by a value this key pins and
/// authenticates what it returns, and those indexes are insert-once with no removal, so a
/// later root returns the same value at every key an earlier replay read. Keeping the roots
/// would only force the cold path after every epoch or ledger ingest.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RetentionKeyV1 {
    /// Scheme id and verifier manifest digest of the installed artifacts.
    installation: ([u8; 32], [u8; 32]),
    wallet: [u8; 32],
    /// The full route: same-program Receive aliases share one prover instance.
    route: OperationRoute,
    sequence: u128,
    /// Custody digest of the selected capsule.
    capsule: [u8; 32],
    /// Fold digest of the predecessor's recorded Ω; zero for Bootstrap.
    predecessor: [u8; 32],
    /// SHA-256 of the canonical predecessor and successor source records and of the retained
    /// preparation (request, native plan, source and draft).
    sources: [[u8; 32]; 3],
    /// The predecessor pending-map root and the credit-tree root the view starts from.
    pending: [u8; 32],
    credits: [u8; 32],
}

impl RetentionKeyV1 {
    /// Read the key of the sub-proof `step` is selected for, before any input derivation
    /// touches `custody`.
    ///
    /// # Errors
    /// An invalid predecessor record or a canonical encoding failure.
    pub(super) fn new(
        worker: &NativeFoldWorkerV1,
        route: OperationRoute,
        step: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        custody: &FoldCustodyV1<'_>,
    ) -> Result<Self, Error> {
        let verifier = worker.installed.verifier();
        let body = step.frozen.capsule.body();
        Ok(Self {
            installation: (verifier.scheme().scheme_id(), verifier.manifest_digest()),
            wallet: body.wallet_id,
            route,
            sequence: body.statement.sequence,
            capsule: step.frozen.capsule.custody_digest(),
            predecessor: predecessor
                .map(KagemushaWalletFoldRecordV1::fold_digest)
                .transpose()
                .map_err(|_| Error::Invalid("predecessor fold"))?
                .unwrap_or([0; 32]),
            sources: custody.source_digests()?,
            pending: custody.pending_root(),
            credits: custody.credit_root(),
        })
    }
}

/// SHA-256 identity of one durable checkpoint payload. The coordinator chain-verified the
/// durable list against its manifest in this turn, so equal identities in order are equal
/// bytes.
pub(super) fn payload_digest(payload: &PrivateArchiveBytes) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"KAGEMUSHA retained fold payload v1");
    digest.update(payload.as_slice());
    digest.finalize().into()
}

/// Whether a state retained under `retained`, whose restored payloads have the identities
/// `held`, may be resumed by the sub-proof with `key` over the durable list `durable`: the
/// same key, and `held` a byte-exact prefix of `durable`.
pub(super) fn resumable(
    retained: &RetentionKeyV1,
    held: &[[u8; 32]],
    key: &RetentionKeyV1,
    durable: &[[u8; 32]],
) -> bool {
    retained == key && durable.starts_with(held)
}

/// What one sub-proof leaves for the next sub-proof of its step.
pub(super) struct RetainedFoldV1 {
    pub(super) key: RetentionKeyV1,
    /// Identities of the durable payloads already restored into `stage`, in order. Never the
    /// checkpoint the leaving sub-proof produced, and never the payload bytes.
    pub(super) held: Vec<[u8; 32]>,
    /// The step's lineage public fields, exactly as the cold derivation computed them.
    pub(super) public: KagemushaWalletLineagePublicV1,
    pub(super) stage: RetainedStageV1,
}

/// The phase of the step the retained state belongs to.
pub(super) enum RetainedStageV1 {
    /// Before every Q source exists.
    Q(Box<RetainedQV1>),
    /// After the family session was prepared.
    Chain(Box<RetainedChainV1>),
}

/// Derived inputs of a step that has not prepared its family session yet.
pub(super) struct RetainedQV1 {
    /// The authenticated owner credential, kept for the lineage fields of the first A/W
    /// sub-proof.
    pub(super) owner: AuthenticatedCredentialV1,
    pub(super) fields: Fields,
    pub(super) q_sources: q::QSourcesV1,
    /// The Q chain restored so far; `None` while σ came from fresh coins.
    pub(super) q: Option<Box<q::QStateV1>>,
}

/// A step whose family session is prepared.
pub(super) struct RetainedChainV1 {
    pub(super) public_fields: [Fp; 18],
    pub(super) family: FamilyStateV1,
}

impl NativeFoldWorkerV1 {
    /// The previous sub-proof's state, when it belongs to `key`, the payloads it restored are a
    /// byte-exact prefix of `durable`, and its family session resumes on this installed prover
    /// instance. Anything else is dropped and the caller runs the cold path in this call; a
    /// refused resume is matched here, never mapped to a proof verdict.
    pub(super) fn admit(
        &self,
        retained: FoldRetentionV1,
        key: &RetentionKeyV1,
        durable: &[[u8; 32]],
        q_count: usize,
    ) -> Option<RetainedFoldV1> {
        let RetainedFoldV1 {
            key: retained_key,
            held,
            public,
            stage,
        } = retained.downcast::<RetainedFoldV1>()?;
        if !resumable(&retained_key, &held, key, durable) {
            return None;
        }
        let stage = match stage {
            RetainedStageV1::Q(q) if held.len() == q.q.as_ref().map_or(0, |q| q.restored()) => {
                RetainedStageV1::Q(q)
            }
            RetainedStageV1::Chain(chain) if held.len() >= q_count => {
                let RetainedChainV1 {
                    public_fields,
                    family,
                } = *chain;
                RetainedStageV1::Chain(Box::new(RetainedChainV1 {
                    public_fields,
                    family: self.admit_family(key.route, family)?,
                }))
            }
            RetainedStageV1::Q(_) | RetainedStageV1::Chain(_) => return None,
        };
        Some(RetainedFoldV1 {
            key: retained_key,
            held,
            public,
            stage,
        })
    }
}

#[cfg(test)]
#[path = "retention_tests.rs"]
mod tests;

/// Test support for deploy-pipeline §7.4 tests 4 and 11 through the genuine worker: flip one
/// bit of the retained preparation identity in the key of a retained state, so the next
/// prepare must take its cold path in the same call. `false` for any other value.
#[cfg(test)]
pub(crate) fn perturb_retained_key_for_test(value: &mut FoldRetentionV1) -> bool {
    let Some(retained) = value.downcast_mut::<RetainedFoldV1>() else {
        return false;
    };
    retained.key.sources[2][0] ^= 1;
    true
}

/// Test-only counts of the fold work retention removes, on the calling thread: cold input
/// derivations (owner replay), warm admissions, strict restores of durable payloads, family
/// session resumptions, σ preparations, and σ preparations from fresh coins. `refusals` counts
/// the prove-time arms that the locked prepare makes unreachable: a refused resume of an
/// admitted session, or an admitted prefix longer than the durable list. Every build still maps
/// both to `Cancelled`; the genuine fold helpers require zero. They decide nothing.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FoldRetentionCountsV1 {
    pub(crate) derivations: u64,
    pub(crate) warm: u64,
    pub(crate) restores: u64,
    pub(crate) resumes: u64,
    pub(crate) sigmas: u64,
    pub(crate) fresh_sigmas: u64,
    pub(crate) refusals: u64,
}

#[cfg(test)]
thread_local! {
    static COUNTS: std::cell::Cell<FoldRetentionCountsV1> = const {
        std::cell::Cell::new(FoldRetentionCountsV1 {
            derivations: 0,
            warm: 0,
            restores: 0,
            resumes: 0,
            sigmas: 0,
            fresh_sigmas: 0,
            refusals: 0,
        })
    };
}

#[cfg(test)]
impl FoldRetentionCountsV1 {
    /// Run `operation` and return its result with the counts it added on this thread.
    pub(crate) fn observe<T>(operation: impl FnOnce() -> T) -> (T, Self) {
        let before = COUNTS.with(std::cell::Cell::get);
        let result = operation();
        let after = COUNTS.with(std::cell::Cell::get);
        (
            result,
            Self {
                derivations: after.derivations - before.derivations,
                warm: after.warm - before.warm,
                restores: after.restores - before.restores,
                resumes: after.resumes - before.resumes,
                sigmas: after.sigmas - before.sigmas,
                fresh_sigmas: after.fresh_sigmas - before.fresh_sigmas,
                refusals: after.refusals - before.refusals,
            },
        )
    }
}

/// Count one event on this thread (tests only).
#[cfg(test)]
pub(super) fn count(update: impl FnOnce(&mut FoldRetentionCountsV1)) {
    COUNTS.with(|counts| {
        let mut value = counts.get();
        update(&mut value);
        counts.set(value);
    });
}
