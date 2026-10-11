//! Ordered persisted sub-proofs, recorded Ω identities and native CreditStatus construction.

use super::fold_custody::FoldSourcesV1;
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
        store: &'a mut dyn ObjectStore,
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
    /// Background work is disabled or a payment holds priority.
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
    fn fold_seed(
        &mut self,
        manifest: &manifest::Manifest,
        before: Option<&ReleasedStep>,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        after: &ReleasedStep,
    ) -> Result<Option<FoldSeed>, Error> {
        let capsule = valid(after.frozen.capsule.capsule_digest())?;
        if manifest
            .capsule_sources
            .get(&mut self.archive, &capsule)?
            .is_none()
        {
            if after.frozen.capsule.kind == KagemushaWalletOperationKindV1::Bootstrap
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
    fn verify_fold_bytes(
        &mut self,
        step: &ReleasedStep,
        bytes: &[u8],
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
        if r.first_sequence != c.statement.sequence
            || r.sequence != c.statement.sequence
            || r.head != c.statement.successor
            || r.capsule_digest != valid(c.capsule_digest())?
            || r.scheme_id != self.scheme_id
            || r.wallet_id != self.wallet_id
            || public.credential_digest != c.statement.credential_digest
            || public.payment_key != step.frozen.credential.body.payment_key
            || public.relation_id != c.statement.relation_id
            || public.lifecycle != c.statement.lifecycle
            || public.policy_epoch != c.successor_state.core.policy_epoch
            || public.enabled_controls != c.successor_state.core.enabled_controls
            || (fold.burned && c.kind != KagemushaWalletOperationKindV1::Receive)
        {
            return Err(Error::WitnessLost("fold head binding"));
        }
        if self
            .verified_folds
            .get(&c.statement.sequence)
            .map(Vec::as_slice)
            != Some(bytes)
        {
            self.proofs.verify_lineage(&r.lineage, cancellation)?;
        }
        // Only the most recently used Ω is cached; history must not accumulate in RAM.
        self.verified_folds.clear();
        self.verified_folds
            .insert(c.statement.sequence, bytes.to_vec());
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
        if let Some(token) = cancellation {
            token.check()?;
        }
        let (_, manifest) = self.manifest()?;
        let sequence = step.frozen.capsule.statement.sequence;
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
        let fold = self.verify_fold_bytes(step, &bytes, cancellation)?;
        Ok(Some(fold))
    }
    fn record_credit(
        tree: &mut credit_tree::CreditTree,
        store: &mut impl ObjectStore,
        step: &ReleasedStep,
        burned: bool,
    ) -> Result<(), Error> {
        let c = &step.frozen.capsule;
        if let KagemushaWalletEffectV1::Receive { credit_id, .. } = c.statement.effect {
            tree.record(
                store,
                &KagemushaWalletCreditDigestLeafV1 {
                    credit_id,
                    payment_digest: c.payment_digest,
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
    ) -> Result<(u32, [u8; 32], Vec<Vec<u8>>), Error> {
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
                        sequence: c.statement.sequence,
                        ordinal,
                    },
                    layout.record_limit()?,
                )?
                .ok_or(Error::WitnessLost("checkpoint gap"))?;
            let checkpoint: Checkpoint = archive::decode(&bytes)?;
            if checkpoint.ordinal != ordinal
                || checkpoint.previous != previous
                || checkpoint.capsule_digest != valid(c.capsule_digest())?
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
    /// Prove or adopt at most one persisted sub-proof. Index roots and exact Ω identity become
    /// durable under the source marker before success. Payment preemption releases workspaces.
    ///
    /// # Errors
    /// Native proof errors, cancellation, missing witnesses or uncertain archive publication.
    /// An error never undoes a selected Send or releases its retained Payment bytes.
    pub fn fold_once(&mut self) -> Result<FoldStatus, Error> {
        let Some(guard) = self.scheduler.start() else {
            return Ok(FoldStatus::Idle);
        };
        let (manifest_digest, mut manifest) = self.sync_manifest()?;
        let Some(last) = manifest.indexed else {
            return Ok(FoldStatus::CaughtUp);
        };
        let sequence = manifest.folded.map_or(Ok(0), |seq| {
            seq.checked_add(1)
                .ok_or(Error::Invalid("sequence overflow"))
        })?;
        let predecessor_step = manifest
            .folded
            .map(|previous| self.indexed_step(&manifest, previous))
            .transpose()?;
        let predecessor = if let Some(step) = predecessor_step.as_ref() {
            let fold = self
                .read_fold_cancellable(step, Some(&guard.token))?
                .ok_or(Error::WitnessLost("fold predecessor"))?;
            if fold.record.lineage.public.credit_digest_root != manifest.credit_tree.root() {
                return Err(Error::WitnessLost("credit tree root"));
            }
            Some(fold.record)
        } else {
            None
        };
        if sequence > last {
            return Ok(FoldStatus::CaughtUp);
        }
        let step = self.indexed_step(&manifest, sequence)?;
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
        let result = if let Some(bytes) = existing_fold.as_ref() {
            let fold = self.verify_fold_bytes(&step, bytes, Some(&guard.token))?;
            FoldProgress::Complete {
                lineage: fold.record.lineage,
                burned: fold.burned,
            }
        } else if let Some(bytes) = existing_checkpoint.as_ref() {
            let candidate: Checkpoint = archive::decode(bytes)?;
            FoldProgress::Checkpoint(candidate.proof)
        } else {
            let mut view = seed
                .as_ref()
                .map(|seed| seed.view(&mut self.archive, predecessor_step.as_ref(), &step))
                .transpose()?;
            self.proofs.fold_next(
                &step,
                predecessor.as_ref(),
                &checkpoints,
                view.as_mut(),
                &guard.token,
            )?
        };
        guard.token.check()?;
        match result {
            FoldProgress::Checkpoint(proof) => {
                let layout = *schedule
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
                    capsule_digest: valid(step.frozen.capsule.capsule_digest())?,
                    predecessor_fold: predecessor
                        .as_ref()
                        .map(KagemushaWalletFoldRecordV1::fold_digest)
                        .transpose()
                        .map_err(|_| Error::Invalid("predecessor fold"))?
                        .unwrap_or([0; 32]),
                    previous,
                    ordinal,
                    proof,
                };
                let bytes = archive::encode(&checkpoint)?;
                if existing_checkpoint
                    .as_ref()
                    .is_some_and(|existing| *existing != bytes)
                {
                    return Err(Error::WitnessLost("interrupted checkpoint binding"));
                }
                self.archive
                    .put(ArchiveKey::Checkpoint { sequence, ordinal }, &bytes)?;
                manifest.checkpoint_count =
                    ordinal.checked_add(1).ok_or(Error::Invalid("ordinal"))?;
                manifest.checkpoint_digest = digest("wallet-fold-checkpoint", &bytes);
                self.publish_manifest(manifest_digest, &manifest)?;
                Ok(FoldStatus::Checkpoint { sequence, ordinal })
            }
            FoldProgress::Complete { lineage, burned } => {
                if usize::try_from(ordinal).ok() != Some(schedule.len()) {
                    return Err(Error::Proof("premature final Ω"));
                }
                self.proofs.verify_lineage(&lineage, Some(&guard.token))?;
                if let Some(seed) = &seed {
                    let mut view =
                        seed.view(&mut self.archive, predecessor_step.as_ref(), &step)?;
                    match step.frozen.capsule.kind {
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
                        &step,
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
                    head: c.statement.successor,
                    capsule_digest: valid(c.capsule_digest())?,
                    lineage,
                };
                let bytes = archive::encode(&RecordedFold { record, burned })?;
                self.verify_fold_bytes(&step, &bytes, Some(&guard.token))?;
                if existing_fold
                    .as_ref()
                    .is_some_and(|existing| *existing != bytes)
                {
                    return Err(Error::WitnessLost("interrupted Ω identity"));
                }
                guard.token.check()?;
                self.archive.put(ArchiveKey::Fold(sequence), &bytes)?;
                let identity = digest("wallet-recorded-fold", &bytes);
                let mut entry = self.step_entry(&manifest, sequence)?;
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
                self.publish_manifest(manifest_digest, &manifest)?;
                Ok(FoldStatus::Folded(sequence))
            }
        }
    }
    /// Construct CreditStatus from the latest covering recorded Ω and a bounded persistent
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
            statement: step.frozen.capsule.statement.clone(),
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
