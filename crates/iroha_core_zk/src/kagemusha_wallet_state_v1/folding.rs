//! Ordered persisted sub-proofs, recorded Ω identities and native `CreditStatus` construction.
//!
//! One sub-proof runs in three phases: a locked prepare under the wallet owner, a proof
//! without it, and a locked publication that re-checks the fold fields. The background
//! slot is held from prepare until the proof finishes, so payment preemption still joins
//! the proof, while ingests and status reads take the wallet owner during it.

use std::ops::ControlFlow;

use super::fold_custody::FoldSourcesV1;
use super::fold_metrics::FoldTurnV1;
use super::scheduling::{FoldGuard, FoldPublicationV1};
use super::*;
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1 as digest;

struct FoldSeed {
    sources: FoldSourcesV1,
    credits: credit_tree::CreditTree,
    pending: map_tree::PersistentMapV1,
}
impl FoldSeed {
    fn view<'a>(
        &self,
        store: &'a mut dyn ObjectWorkspace,
        before: Option<&'a ReleasedStep>,
        after: &'a ReleasedStep,
    ) -> Result<FoldCustodyV1<'a>, Error> {
        FoldCustodyV1::new(
            store,
            before,
            after,
            self.sources.clone(),
            self.credits.clone(),
            self.pending.clone(),
        )
    }
}

/// Result of one cooperative background scheduling turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldStatus {
    /// Background work is disabled, a payment holds priority, custody is Pending or another
    /// sub-proof is proving.
    Idle,
    /// Every released head is folded.
    CaughtUp,
    /// One sub-proof was made durable.
    Checkpoint {
        /// Head sequence.
        sequence: u128,
        /// Zero-based sub-proof ordinal.
        ordinal: u32,
    },
    /// A self-verified Ω is durably recorded for this head.
    Folded(u128),
}

/// A finished fold turn with the fold backlog of the source-selected manifest it ended on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldTurnStatusV1 {
    /// The turn's status.
    pub status: FoldStatus,
    /// Released heads still needing local folds under the manifest this turn synced or
    /// published, counted like [`Snapshot::fold_backlog`]; `None` for an idle turn, before
    /// Bootstrap, or when the count is not representable. A scheduling hint only: it grants
    /// no Send, Unload, Request or device move, and [`Coordinator::snapshot`] stays the view
    /// of fold progress.
    pub backlog: Option<u128>,
}

impl FoldTurnStatusV1 {
    const IDLE: Self = Self {
        status: FoldStatus::Idle,
        backlog: None,
    };

    /// `status` with the backlog of `manifest`, by the checked formula of
    /// [`Coordinator::snapshot`]: `indexed - folded`, or `indexed + 1` before the first fold.
    fn of(status: FoldStatus, manifest: &manifest::Manifest) -> Self {
        let backlog = manifest.indexed.and_then(|indexed| {
            manifest.folded.map_or_else(
                || indexed.checked_add(1),
                |folded| indexed.checked_sub(folded),
            )
        });
        Self { status, backlog }
    }
}

/// One selected sub-proof between its locked prepare and its locked publication.
///
/// It holds the background slot and owns the native job with the fold fields it was prepared
/// from, but no custody, archive or original-store handle. Prove it after releasing the
/// wallet owner, then publish the result under that owner again.
pub struct FoldJobV1 {
    guard: FoldGuard,
    turn: FoldTurnV1,
    prepared: Prepared,
    native: Box<dyn NativeFoldJobV1>,
}

/// A proved sub-proof awaiting its locked publication. It no longer holds the background
/// slot; its publication re-checks the fold fields and discards a stale proof. It holds no
/// retained native state either, only the publication identity that settles the value its
/// sub-proof parked in the scheduler: dropping it unpublished discards that value.
pub struct ProvedFoldV1 {
    turn: FoldTurnV1,
    ingests: u32,
    prepared: Prepared,
    progress: FoldProgress,
    publication: FoldPublicationV1,
}

/// The selected manifest and fold fields one sub-proof was prepared from.
struct Prepared {
    manifest_digest: [u8; 32],
    manifest: manifest::Manifest,
    sequence: u128,
    ordinal: u32,
    previous: [u8; 32],
    schedule: Vec<CheckpointLayout>,
    step: ReleasedStep,
    predecessor_step: Option<ReleasedStep>,
    predecessor: Option<KagemushaWalletFoldRecordV1>,
    // Source-bound identity of the predecessor's recorded Ω.
    predecessor_identity: Option<Vec<u8>>,
    seed: Option<FoldSeed>,
}

impl FoldJobV1 {
    /// Prove the prepared sub-proof; call it without the wallet owner. A payment, activity or
    /// close signal cancels it at a cooperative boundary and releases its work; an ingest or
    /// status read never does. A finished proof releases the background slot before its
    /// publication, so a payment never waits for that publication's wallet owner.
    ///
    /// # Errors
    /// `Cancelled` on preemption, or a native proof error. Nothing is published.
    pub fn prove(self) -> Result<ProvedFoldV1, Error> {
        let Self {
            guard,
            turn,
            prepared,
            native,
        } = self;
        fold_metrics::enter(FoldPhaseV1::Prove);
        let proved = native.prove(&guard.token).and_then(|proved| {
            guard.token.check()?;
            Ok(proved)
        });
        match proved {
            Ok((progress, retained)) => {
                // The wait for the wallet owner belongs to the publication.
                fold_metrics::enter(FoldPhaseV1::Publish);
                // What the native owner retained is parked under this attempt as the slot is
                // released; the proved job keeps only its publication identity.
                let (ingests, publication) = guard.release(retained);
                Ok(ProvedFoldV1 {
                    ingests,
                    turn,
                    prepared,
                    progress,
                    publication,
                })
            }
            Err(error) => {
                // Reported while the slot is held, so a joining payment returns after it.
                guard.report(turn, Err(&error));
                Err(error)
            }
        }
    }
}

/// Session-local reuse of byte-identical Ω, including public/deferred values and proof bytes.
#[derive(Default)]
pub struct LineageCache {
    verified: Option<Vec<u8>>,
}

impl LineageCache {
    /// Verify Ω unless every canonical byte matches the last fully verified Ω in this session.
    /// Returns true when verification was reused.
    ///
    /// # Errors
    /// Invalid Ω or a failing native decide. Failures never populate the cache.
    pub fn verify(
        &mut self,
        native: &impl NativeProofs,
        lineage: &KagemushaWalletLineageV1,
    ) -> Result<bool, Error> {
        valid(lineage.validate())?;
        let bytes = lineage.bytes();
        if self.verified.as_ref() == Some(&bytes) {
            return Ok(true);
        }
        native.verify_lineage(lineage, None)?;
        self.verified = Some(bytes);
        Ok(false)
    }
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    /// Inspect the authenticated cursor before a bounded engineering continuation.
    /// This does not verify a checkpoint or grant permission to skip native restoration.
    #[cfg(test)]
    pub(crate) fn fold_checkpoint_cursor_for_test(&mut self) -> Result<(u128, u32), Error> {
        let (_, manifest) = self.sync_manifest()?;
        let sequence = manifest.folded.map_or(Ok(0), |sequence| {
            sequence
                .checked_add(1)
                .ok_or(Error::Invalid("sequence overflow"))
        })?;
        Ok((sequence, manifest.checkpoint_count))
    }

    fn fold_seed(
        &mut self,
        manifest: &manifest::Manifest,
        before: Option<&ReleasedStep>,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        after: &ReleasedStep,
    ) -> Result<Option<FoldSeed>, Error> {
        let capsule = after.frozen.capsule.custody_digest();
        if manifest
            .capsule_sources
            .get(&mut self.archive, &capsule)?
            .is_none()
        {
            if after.frozen.capsule.body().kind == KagemushaWalletOperationKindV1::Bootstrap
                || manifest
                    .capsule_plans
                    .get(&mut self.archive, &capsule)?
                    .is_some()
            {
                return Err(Error::WitnessLost("fold preparation snapshot"));
            }
            return Ok(None);
        }
        let after_source = self.source_custody(manifest, after)?;
        let before_source = before
            .map(|step| self.source_custody(manifest, step))
            .transpose()?;
        let mut pending = before_source
            .as_ref()
            .map(|source| source.maps.pending().clone())
            .unwrap_or_default();
        if let Some(predecessor) = predecessor {
            if let Some(address) = manifest.fold_pending.get(
                &mut self.archive,
                &manifest::sequence_key(predecessor.sequence),
            )? {
                let address: [u8; 32] = address
                    .try_into()
                    .map_err(|_| Error::WitnessLost("fold pending address"))?;
                pending = archive::decode(&self.archive.read_object(&address, 2048)?)?;
            }
            pending.validate()?;
            if pending.root() != predecessor.lineage.public.pending_outgoing_root
                || manifest.credit_tree.root() != predecessor.lineage.public.credit_digest_root
            {
                return Err(Error::WitnessLost("fold predecessor map roots"));
            }
        }
        let preparation = self.transition_preparation(manifest, &after.frozen)?;
        Ok(Some(FoldSeed {
            sources: FoldSourcesV1 {
                before: before_source,
                after: after_source,
                preparation,
                issued: manifest.issued_requests,
                anchors: manifest.direct_anchors,
                epochs: manifest.finality_epochs,
            },
            credits: manifest.credit_tree.clone(),
            pending,
        }))
    }
    /// Decode and bind a recorded Ω to its head, verifying the Ω in full unless these exact
    /// record bytes were verified in this session, or `verified` holds the canonical bytes of
    /// the exact lineage that `fold_once` just verified in full and the record carries it.
    pub(super) fn verify_fold_bytes(
        &mut self,
        step: &ReleasedStep,
        bytes: &[u8],
        verified: Option<&[u8]>,
        cancellation: Option<&Cancellation>,
    ) -> Result<RecordedFold, Error> {
        if let Some(token) = cancellation {
            token.check()?;
        }
        let c = &step.frozen.capsule;
        let fold: RecordedFold = archive::decode(bytes)?;
        valid(fold.record.to_canonical_bytes())?;
        let r = &fold.record;
        let public = &r.lineage.public;
        if r.first_sequence != c.body().statement.sequence
            || r.sequence != c.body().statement.sequence
            || r.head != c.body().statement.successor
            || r.capsule_digest != c.custody_digest()
            || r.scheme_id != self.scheme_id
            || r.wallet_id != self.wallet_id
            || public.credential_digest != c.body().statement.credential_digest
            || public.payment_key != step.frozen.credential.body.payment_key
            || public.relation_id != c.body().statement.relation_id
            || public.lifecycle != c.body().statement.lifecycle
            || public.policy_epoch != c.body().successor_state.core.policy_epoch
            || public.enabled_controls != c.body().successor_state.core.enabled_controls
            || (fold.burned && c.body().kind != KagemushaWalletOperationKindV1::Receive)
        {
            return Err(Error::WitnessLost("fold head binding"));
        }
        let reused = self
            .verified_folds
            .get(&c.body().statement.sequence)
            .map(Vec::as_slice)
            == Some(bytes)
            || verified.is_some_and(|lineage| r.lineage.bytes() == lineage);
        if !reused {
            self.proofs.verify_lineage(&r.lineage, cancellation)?;
        }
        // Only the most recently used Ω is cached; history must not accumulate in RAM.
        self.verified_folds.clear();
        self.verified_folds
            .insert(c.body().statement.sequence, bytes.to_vec());
        Ok(fold)
    }
    pub(super) fn read_fold(&mut self, step: &ReleasedStep) -> Result<Option<RecordedFold>, Error> {
        self.read_fold_cancellable(step, None)
    }
    pub(super) fn read_fold_cancellable(
        &mut self,
        step: &ReleasedStep,
        cancellation: Option<&Cancellation>,
    ) -> Result<Option<RecordedFold>, Error> {
        Ok(self
            .read_fold_identified(step, cancellation)?
            .map(|(fold, _)| fold))
    }
    /// [`Self::read_fold_cancellable`] with the source-bound Ω identity it was read under.
    fn read_fold_identified(
        &mut self,
        step: &ReleasedStep,
        cancellation: Option<&Cancellation>,
    ) -> Result<Option<(RecordedFold, Vec<u8>)>, Error> {
        if let Some(token) = cancellation {
            token.check()?;
        }
        let (_, manifest) = self.manifest()?;
        let sequence = step.frozen.capsule.body().statement.sequence;
        let expected = manifest
            .folds
            .get(&mut self.archive, &manifest::sequence_key(sequence))?;
        let Some(expected) = expected else {
            if manifest.folded.is_some_and(|last| sequence <= last) {
                return Err(Error::WitnessLost("fold index gap"));
            }
            return Ok(None);
        };
        let bytes = self
            .archive
            .get(
                ArchiveKey::Fold(sequence),
                KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1 + archive::METADATA_BOUND,
            )?
            .ok_or(Error::WitnessLost("recorded Ω"))?;
        if expected != digest("wallet-recorded-fold", &bytes) {
            return Err(Error::WitnessLost("source-bound Ω identity"));
        }
        let fold = self.verify_fold_bytes(step, &bytes, None, cancellation)?;
        Ok(Some((fold, expected)))
    }
    fn record_credit(
        tree: &mut credit_tree::CreditTree,
        store: &mut impl ObjectStore,
        step: &ReleasedStep,
        burned: bool,
    ) -> Result<(), Error> {
        let c = &step.frozen.capsule;
        if let KagemushaWalletEffectV1::Receive { credit_id, .. } = c.body().statement.effect {
            tree.record(
                store,
                &KagemushaWalletCreditDigestLeafV1 {
                    credit_id,
                    payment_digest: c.body().payment_digest,
                    burned,
                },
            )?;
        } else if burned {
            return Err(Error::Invalid("non-Receive burn flag"));
        }
        Ok(())
    }
    fn checkpoints(
        &mut self,
        step: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        schedule: &[CheckpointLayout],
        manifest: &manifest::Manifest,
    ) -> Result<(u32, [u8; 32], Vec<PrivateArchiveBytes>), Error> {
        if usize::try_from(manifest.checkpoint_count)
            .ok()
            .is_none_or(|count| count > schedule.len())
        {
            return Err(Error::WitnessLost("checkpoint count"));
        }
        let c = &step.frozen.capsule;
        let mut previous = [0; 32];
        let mut originals = Vec::with_capacity(manifest.checkpoint_count as usize);
        let predecessor_fold = predecessor
            .map(KagemushaWalletFoldRecordV1::fold_digest)
            .transpose()
            .map_err(|_| Error::Invalid("predecessor fold"))?
            .unwrap_or([0; 32]);
        for ordinal in 0..manifest.checkpoint_count {
            let layout =
                schedule[usize::try_from(ordinal).map_err(|_| Error::Invalid("ordinal"))?];
            let bytes = self
                .archive
                .get(
                    ArchiveKey::Checkpoint {
                        sequence: c.body().statement.sequence,
                        ordinal,
                    },
                    layout.record_limit()?,
                )?
                .ok_or(Error::WitnessLost("checkpoint gap"))?;
            let checkpoint: Checkpoint = archive::decode(&bytes)?;
            if checkpoint.ordinal != ordinal
                || checkpoint.previous != previous
                || checkpoint.capsule_digest != c.custody_digest()
                || checkpoint.predecessor_fold != predecessor_fold
                || checkpoint.layout != layout
                || checkpoint.proof.len()
                    != usize::try_from(layout.payload_bytes)
                        .map_err(|_| Error::Invalid("checkpoint size"))?
            {
                return Err(Error::WitnessLost("checkpoint chain"));
            }
            previous = digest("wallet-fold-checkpoint", &bytes);
            originals.push(checkpoint.proof);
        }
        if previous != manifest.checkpoint_digest {
            return Err(Error::WitnessLost("source-bound checkpoint identity"));
        }
        Ok((manifest.checkpoint_count, previous, originals))
    }
    /// Prove or adopt at most one persisted sub-proof for an exclusive owner: the locked
    /// [`Self::fold_prepare`], [`FoldJobV1::prove`] and the publication, while this caller
    /// holds the coordinator throughout. Index roots and exact Ω identity become durable under
    /// the source marker before success. Payment preemption releases workspaces. A turn that
    /// selected a sub-proof is reported to the scheduler's fold observer (observation only).
    /// A host that releases the wallet owner while proving publishes with
    /// [`Self::fold_publish`] instead.
    ///
    /// # Errors
    /// Native proof errors, cancellation, missing witnesses or uncertain archive publication.
    /// An error never undoes a selected Send or releases its retained Payment bytes.
    pub fn fold_once(&mut self) -> Result<FoldStatus, Error> {
        let job = match self.fold_prepare()? {
            ControlFlow::Break(ended) => return Ok(ended.status),
            ControlFlow::Continue(job) => job,
        };
        let ProvedFoldV1 {
            turn,
            ingests,
            mut prepared,
            progress,
            publication,
        } = job.prove()?;
        // This caller held the coordinator since prepare, so the prepared manifest is still
        // the selected one: its compare-and-publish needs no re-check or rebase.
        let result = self.publish_progress(&mut prepared, progress, None, None, None);
        publication.settle(result.as_ref().copied());
        self.scheduler
            .report(turn, result.as_ref().copied(), None, ingests);
        result
    }

    /// The locked first phase of one sub-proof. Under the wallet owner it selects the next
    /// sub-proof, re-chains its durable checkpoints, and either adopts an interrupted
    /// publication byte-for-byte or prepares the owned job: native replay, inputs and the
    /// revalidated proving originals of the selected stage. A caught-up turn ends right after
    /// the manifest sync and reads no step, recorded Ω or credit root. `Break` ends the turn
    /// with its status and backlog; `Continue` carries the job to [`FoldJobV1::prove`] once
    /// the owner is released. A turn that ends here is reported to the scheduler's fold
    /// observer before the background slot is released (observation only).
    ///
    /// # Errors
    /// Native preparation errors, cancellation, missing witnesses or uncertain archive
    /// publication. An error never undoes a selected Send or releases its retained Payment.
    pub fn fold_prepare(&mut self) -> Result<ControlFlow<FoldTurnStatusV1, FoldJobV1>, Error> {
        let Some(guard) = self.scheduler.start() else {
            return Ok(ControlFlow::Break(FoldTurnStatusV1::IDLE));
        };
        // What the previous sub-proof's checkpoint publication retained. Only the native
        // owner reads it, for the same key and a byte-exact durable prefix; every turn that
        // proves nothing drops it.
        let retained = guard.take_retained();
        let mut turn = FoldTurnV1::start();
        let result = match self.fold_turn(&guard, &mut turn, retained) {
            Ok(ControlFlow::Continue((prepared, native))) => {
                return Ok(ControlFlow::Continue(FoldJobV1 {
                    guard,
                    turn,
                    prepared,
                    native,
                }));
            }
            Ok(ControlFlow::Break(ended)) => Ok(ended),
            Err(error) => Err(error),
        };
        guard.report(turn, result.as_ref().map(|ended| ended.status));
        result.map(ControlFlow::Break)
    }

    /// The locked last phase of a sub-proof proved without the wallet owner. It publishes only
    /// if the fold fields the proof was prepared from are unchanged: the folded head, the
    /// checkpoint count and digest, the step's capsule, the predecessor Ω and an empty
    /// publication slot. A head that became Pending discards this proof and parks the next
    /// prepare until its frozen operation finishes. Unrelated released Advance and ingest writes
    /// are rebased onto the selected manifest; otherwise the proof is discarded, never published,
    /// and the next turn resumes from durable state. Index roots and exact Ω identity become
    /// durable under the source marker before success. The turn is reported to the scheduler's
    /// fold observer; its backlog is that of the published manifest.
    ///
    /// # Errors
    /// `Cancelled` for a discarded proof, missing witnesses, a rejected Ω or uncertain archive
    /// publication. An error never undoes a selected Send or releases its retained Payment.
    pub fn fold_publish(&mut self, proved: ProvedFoldV1) -> Result<FoldTurnStatusV1, Error> {
        let ProvedFoldV1 {
            mut turn,
            ingests,
            mut prepared,
            progress,
            publication,
        } = proved;
        let result = self.publish_rebased(&mut prepared, progress, &mut turn);
        publication.settle(result.as_ref().copied());
        self.scheduler
            .report(turn, result.as_ref().copied(), None, ingests);
        result.map(|status| FoldTurnStatusV1::of(status, &prepared.manifest))
    }

    fn fold_turn(
        &mut self,
        guard: &FoldGuard,
        turn: &mut FoldTurnV1,
        retained: Option<FoldRetentionV1>,
    ) -> Result<ControlFlow<FoldTurnStatusV1, (Prepared, Box<dyn NativeFoldJobV1>)>, Error> {
        let (manifest_digest, manifest) = match self.sync_manifest() {
            Ok(selected) => selected,
            // Selected custody must finish its frozen operation before any fold can start.
            // Park without a worker error or another wake; the completing payment guard
            // wakes the owner again. Do not mask provider/storage uncertainty as Pending.
            Err(Error::Pending) => return Ok(ControlFlow::Break(FoldTurnStatusV1::IDLE)),
            Err(error) => return Err(error),
        };
        let Some(last) = manifest.indexed else {
            return Ok(ControlFlow::Break(FoldTurnStatusV1::of(
                FoldStatus::CaughtUp,
                &manifest,
            )));
        };
        // Caught up (`manifest()` refuses a folded head past the index): the wake reads no
        // step, recorded Ω or credit root. A turn that selects a sub-proof checks them all
        // below; a folded-state read checks the ones it uses.
        if manifest.folded == Some(last) {
            return Ok(ControlFlow::Break(FoldTurnStatusV1::of(
                FoldStatus::CaughtUp,
                &manifest,
            )));
        }
        let sequence = manifest.folded.map_or(Ok(0), |seq| {
            seq.checked_add(1)
                .ok_or(Error::Invalid("sequence overflow"))
        })?;
        turn.select(sequence, manifest.checkpoint_count);
        fold_metrics::enter(FoldPhaseV1::ReadFold);
        let predecessor_step = manifest
            .folded
            .map(|previous| self.indexed_step(&manifest, previous))
            .transpose()?;
        let (predecessor, predecessor_identity) = if let Some(step) = predecessor_step.as_ref() {
            let (fold, identity) = self
                .read_fold_identified(step, Some(&guard.token))?
                .ok_or(Error::WitnessLost("fold predecessor"))?;
            if fold.record.lineage.public.credit_digest_root != manifest.credit_tree.root() {
                return Err(Error::WitnessLost("credit tree root"));
            }
            (Some(fold.record), Some(identity))
        } else {
            (None, None)
        };
        fold_metrics::enter(FoldPhaseV1::FoldSeed);
        let step = self.indexed_step(&manifest, sequence)?;
        turn.operation(step.frozen.capsule.body().kind);
        let seed = self.fold_seed(
            &manifest,
            predecessor_step.as_ref(),
            predecessor.as_ref(),
            &step,
        )?;
        let schedule = {
            let mut view = seed
                .as_ref()
                .map(|seed| seed.view(&mut self.archive, predecessor_step.as_ref(), &step))
                .transpose()?;
            self.proofs
                .fold_schedule(&step, predecessor.as_ref(), view.as_mut())?
        };
        for layout in &schedule {
            layout.record_limit()?;
        }
        let (ordinal, previous, checkpoints) =
            self.checkpoints(&step, predecessor.as_ref(), &schedule, &manifest)?;
        if usize::try_from(ordinal).ok() == Some(schedule.len()) {
            fold_metrics::stage(FoldStageV1::Omega);
        }
        guard.token.check()?;
        // A completed but unacknowledged publication is adopted byte-for-byte, never re-proved.
        let existing_fold = self.archive.get(
            ArchiveKey::Fold(sequence),
            KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1 + archive::METADATA_BOUND,
        )?;
        let existing_checkpoint = if let Some(layout) =
            schedule.get(usize::try_from(ordinal).map_err(|_| Error::Invalid("ordinal"))?)
        {
            self.archive.get(
                ArchiveKey::Checkpoint { sequence, ordinal },
                layout.record_limit()?,
            )?
        } else {
            None
        };
        let mut prepared = Prepared {
            manifest_digest,
            manifest,
            sequence,
            ordinal,
            previous,
            schedule,
            step,
            predecessor_step,
            predecessor,
            predecessor_identity,
            seed,
        };
        // Canonical bytes of an adopted Ω that verify_fold_bytes just verified in full.
        let mut adopted = None;
        let (progress, existing) = if let Some(bytes) = existing_fold.as_deref() {
            turn.adopting();
            fold_metrics::enter(FoldPhaseV1::Publish);
            let fold = self.verify_fold_bytes(&prepared.step, bytes, None, Some(&guard.token))?;
            adopted = Some(fold.record.lineage.bytes());
            let progress = FoldProgress::Complete {
                lineage: fold.record.lineage,
                burned: fold.burned,
            };
            (progress, bytes)
        } else if let Some(bytes) = existing_checkpoint.as_deref() {
            turn.adopting();
            fold_metrics::enter(FoldPhaseV1::Publish);
            let candidate: Checkpoint = archive::decode(bytes)?;
            (FoldProgress::Checkpoint(candidate.proof), bytes)
        } else {
            fold_metrics::enter(FoldPhaseV1::OwnerReplay);
            let native = {
                let mut view = prepared
                    .seed
                    .as_ref()
                    .map(|seed| {
                        seed.view(
                            &mut self.archive,
                            prepared.predecessor_step.as_ref(),
                            &prepared.step,
                        )
                    })
                    .transpose()?;
                self.proofs.fold_prepare(
                    &prepared.step,
                    prepared.predecessor.as_ref(),
                    checkpoints,
                    view.as_mut(),
                    retained,
                    &guard.token,
                )?
            };
            guard.token.check()?;
            return Ok(ControlFlow::Continue((prepared, native)));
        };
        guard.token.check()?;
        let status = self.publish_progress(
            &mut prepared,
            progress,
            Some(existing),
            adopted,
            Some(&guard.token),
        )?;
        Ok(ControlFlow::Break(FoldTurnStatusV1::of(
            status,
            &prepared.manifest,
        )))
    }

    /// Re-check the fold fields under the selected manifest, then rebase the publication on it.
    fn publish_rebased(
        &mut self,
        prepared: &mut Prepared,
        progress: FoldProgress,
        turn: &mut FoldTurnV1,
    ) -> Result<FoldStatus, Error> {
        let (manifest_digest, manifest) = match self.sync_manifest() {
            Ok(selected) => selected,
            // The proof released its scheduler slot before taking the owner again. A
            // payment may have selected Pending custody in that gap. Discard this proof;
            // the worker's next prepare parks until that frozen operation is released.
            Err(Error::Pending) => {
                turn.discarding();
                return Err(Error::Cancelled);
            }
            Err(error) => return Err(error),
        };
        let selected = &prepared.manifest;
        let unchanged = manifest.folded == selected.folded
            && manifest.checkpoint_count == selected.checkpoint_count
            && manifest.checkpoint_digest == selected.checkpoint_digest
            && self.step_entry(&manifest, prepared.sequence)?.capsule
                == prepared.step.frozen.capsule.custody_digest()
            && manifest
                .folded
                .map(|folded| {
                    manifest
                        .folds
                        .get(&mut self.archive, &manifest::sequence_key(folded))
                })
                .transpose()?
                .flatten()
                == prepared.predecessor_identity
            && self.publication_slot(prepared, &progress)?.is_none();
        if !unchanged {
            // Another writer changed the fold fields while this proof ran without the wallet
            // owner. A stale proof is never published.
            turn.discarding();
            return Err(Error::Cancelled);
        }
        prepared.manifest_digest = manifest_digest;
        prepared.manifest = manifest;
        self.publish_progress(prepared, progress, None, None, None)
    }

    /// Durable bytes already at this sub-proof's publication slot: its checkpoint, or its Ω.
    fn publication_slot(
        &mut self,
        prepared: &Prepared,
        progress: &FoldProgress,
    ) -> Result<Option<PrivateArchiveBytes>, Error> {
        let (sequence, ordinal) = (prepared.sequence, prepared.ordinal);
        match progress {
            FoldProgress::Checkpoint(_) => {
                let layout = prepared
                    .schedule
                    .get(usize::try_from(ordinal).map_err(|_| Error::Invalid("ordinal"))?)
                    .ok_or(Error::Proof("unexpected extra checkpoint"))?;
                self.archive.get(
                    ArchiveKey::Checkpoint { sequence, ordinal },
                    layout.record_limit()?,
                )
            }
            FoldProgress::Complete { .. } => self.archive.get(
                ArchiveKey::Fold(sequence),
                KAGEMUSHA_WALLET_FOLD_RECORD_MAX_BYTES_V1 + archive::METADATA_BOUND,
            ),
        }
    }

    /// Make one sub-proof durable under `prepared.manifest`, the selected manifest. `existing`
    /// holds interrupted bytes being adopted, which must match exactly; `adopted` the
    /// canonical lineage that adoption verified in full.
    fn publish_progress(
        &mut self,
        prepared: &mut Prepared,
        progress: FoldProgress,
        existing: Option<&[u8]>,
        adopted: Option<Vec<u8>>,
        cancellation: Option<&Cancellation>,
    ) -> Result<FoldStatus, Error> {
        let (sequence, ordinal) = (prepared.sequence, prepared.ordinal);
        let manifest = &mut prepared.manifest;
        match progress {
            FoldProgress::Checkpoint(proof) => {
                fold_metrics::enter(FoldPhaseV1::Publish);
                let layout = *prepared
                    .schedule
                    .get(usize::try_from(ordinal).map_err(|_| Error::Invalid("ordinal"))?)
                    .ok_or(Error::Proof("unexpected extra checkpoint"))?;
                if proof.len()
                    != usize::try_from(layout.payload_bytes)
                        .map_err(|_| Error::Invalid("checkpoint size"))?
                {
                    return Err(Error::Proof("checkpoint size"));
                }
                let checkpoint = Checkpoint {
                    layout,
                    capsule_digest: prepared.step.frozen.capsule.custody_digest(),
                    predecessor_fold: prepared
                        .predecessor
                        .as_ref()
                        .map(KagemushaWalletFoldRecordV1::fold_digest)
                        .transpose()
                        .map_err(|_| Error::Invalid("predecessor fold"))?
                        .unwrap_or([0; 32]),
                    previous: prepared.previous,
                    ordinal,
                    proof,
                };
                let bytes = PrivateArchiveBytes::encode(&checkpoint)
                    .map_err(|_| Error::Invalid("private checkpoint encoding"))?;
                if existing.is_some_and(|existing| existing != bytes.as_slice()) {
                    return Err(Error::WitnessLost("interrupted checkpoint binding"));
                }
                self.archive
                    .put(ArchiveKey::Checkpoint { sequence, ordinal }, &bytes)?;
                manifest.checkpoint_count =
                    ordinal.checked_add(1).ok_or(Error::Invalid("ordinal"))?;
                manifest.checkpoint_digest = digest("wallet-fold-checkpoint", &bytes);
                self.publish_manifest(prepared.manifest_digest, manifest)?;
                Ok(FoldStatus::Checkpoint { sequence, ordinal })
            }
            FoldProgress::Complete { lineage, burned } => {
                if usize::try_from(ordinal).ok() != Some(prepared.schedule.len()) {
                    return Err(Error::Proof("premature final Ω"));
                }
                // Exactly one full verification of this Ω, before any credit, pending-map,
                // archive or manifest effect. An adopted record was verified above; reuse
                // requires its exact canonical lineage bytes.
                let verified = lineage.bytes();
                if adopted.as_ref() != Some(&verified) {
                    self.proofs.verify_lineage(&lineage, cancellation)?;
                }
                fold_metrics::enter(FoldPhaseV1::Publish);
                let step = &prepared.step;
                if let Some(seed) = &prepared.seed {
                    let mut view =
                        seed.view(&mut self.archive, prepared.predecessor_step.as_ref(), step)?;
                    match step.frozen.capsule.body().kind {
                        KagemushaWalletOperationKindV1::Receive => {
                            view.credit_record(burned)?;
                        }
                        KagemushaWalletOperationKindV1::Send => {
                            view.pending_insert()?;
                        }
                        KagemushaWalletOperationKindV1::ArchiveSent => {
                            view.pending_remove()?;
                        }
                        _ if burned => return Err(Error::Invalid("non-Receive burn flag")),
                        _ => {}
                    }
                    let (credits, pending) = view.finish(&lineage.public)?;
                    manifest.credit_tree = credits;
                    let address = self
                        .archive
                        .write_object(&archive::encode(&pending)?, 2048)?;
                    manifest.fold_pending = manifest.fold_pending.set(
                        &mut self.archive,
                        manifest::sequence_key(sequence),
                        &address,
                    )?;
                } else {
                    Self::record_credit(
                        &mut manifest.credit_tree,
                        &mut self.archive,
                        step,
                        burned,
                    )?;
                }
                if lineage.public.credit_digest_root != manifest.credit_tree.root() {
                    return Err(Error::Proof("credit-digest root"));
                }
                let c = &step.frozen.capsule;
                let record = KagemushaWalletFoldRecordV1 {
                    version: 1,
                    scheme_id: self.scheme_id,
                    wallet_id: self.wallet_id,
                    first_sequence: sequence,
                    sequence,
                    head: c.body().statement.successor,
                    capsule_digest: c.custody_digest(),
                    lineage,
                };
                let bytes = archive::encode(&RecordedFold { record, burned })?;
                self.verify_fold_bytes(step, &bytes, Some(&verified), cancellation)?;
                if existing.is_some_and(|existing| existing != bytes.as_slice()) {
                    return Err(Error::WitnessLost("interrupted Ω identity"));
                }
                if let Some(token) = cancellation {
                    token.check()?;
                }
                self.archive.put(ArchiveKey::Fold(sequence), &bytes)?;
                let identity = digest("wallet-recorded-fold", &bytes);
                let mut entry = self.step_entry(manifest, sequence)?;
                entry.checkpoints = ordinal;
                manifest.steps = manifest.steps.set(
                    &mut self.archive,
                    manifest::sequence_key(sequence),
                    &archive::encode(&entry)?,
                )?;
                manifest.folds = manifest.folds.set(
                    &mut self.archive,
                    manifest::sequence_key(sequence),
                    &identity,
                )?;
                manifest.folded = Some(sequence);
                manifest.checkpoint_count = 0;
                manifest.checkpoint_digest = [0; 32];
                self.publish_manifest(prepared.manifest_digest, manifest)?;
                Ok(FoldStatus::Folded(sequence))
            }
        }
    }
    /// Construct `CreditStatus` from the latest covering recorded Ω and a bounded persistent
    /// tree opening. The first Payment digest and burn flag survive unrelated later heads.
    ///
    /// # Errors
    /// Unknown/conflicting credit, no covering fold, custody loss or failed native verification.
    pub fn credit_status(
        &mut self,
        credit_id: &[u8; 32],
        payment_digest: &[u8; 32],
    ) -> Result<KagemushaWalletCreditStatusV1, Error> {
        self.status()?;
        let (_, manifest) = self.manifest()?;
        let credit = self
            .indexed_credit(&manifest, credit_id)?
            .ok_or(Error::Invalid("unknown credit"))?;
        if credit.payment_digest != *payment_digest {
            return Err(Error::CreditConflict);
        }
        let sequence = manifest
            .folded
            .filter(|sequence| *sequence >= credit.sequence)
            .ok_or(Error::FoldRequired)?;
        let step = self.indexed_step(&manifest, sequence)?;
        let fold = self
            .read_fold(&step)?
            .ok_or(Error::WitnessLost("covering Ω"))?;
        if fold.record.lineage.public.credit_digest_root != manifest.credit_tree.root() {
            return Err(Error::WitnessLost("credit root"));
        }
        let (leaf, indexed, opening) =
            manifest.credit_tree.opening(&mut self.archive, credit_id)?;
        if leaf.payment_digest != *payment_digest {
            return Err(Error::WitnessLost("credit first identity"));
        }
        let status = KagemushaWalletCreditStatusV1 {
            version: 1,
            statement: step.frozen.capsule.body().statement.clone(),
            proof_digest: valid(step.frozen.capsule.proof_digest())?,
            receipt: step.retained.record.receipt,
            lineage: fold.record.lineage,
            opening: valid(KagemushaWalletCreditOpeningV1::new(
                &leaf, &indexed, &opening,
            ))?,
        };
        valid(status.validate())?;
        self.status()?;
        Ok(status)
    }
}
