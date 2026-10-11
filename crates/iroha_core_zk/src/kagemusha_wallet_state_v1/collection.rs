//! Bounded, source-selected witness collection after a verified covering Ω.
use super::*;

/// Exact indexed-tree nonmembership under the latest locally verified pending-outgoing root.
/// Generic acknowledgements and an ArchiveSent operation name cannot authorize collection.
struct DerivedOutgoingAbsence {
    /// Predecessor leaf bracketing the committed Send credit.
    low: KagemushaWalletIndexedLeafV1,
    /// Canonical depth-32 opening of that leaf.
    opening: KagemushaWalletIndexedOpeningV1,
}

/// At most one bounded collection action is performed by each scheduling call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectionStatus {
    /// A payment has priority or background work is disabled.
    Idle,
    /// A durable collection decision was recorded or one object was removed.
    Progress(u128),
    /// Every selected witness object is removed; permanent replay metadata remains.
    Collected(u128),
}
#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::CollectionIntent")]
pub(super) struct CollectionIntent {
    pub sequence: u128,
    pub covering_sequence: u128,
    pub covering_fold: [u8; 32],
    pub next_checkpoint: u32,
    pub phase: u8,
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    fn collection_outgoing_absence(
        &mut self,
        manifest: &manifest::Manifest,
        fold: &KagemushaWalletFoldRecordV1,
        credit: &[u8; 32],
    ) -> Result<DerivedOutgoingAbsence, Error> {
        let address = manifest
            .fold_pending
            .get(&mut self.archive, &manifest::sequence_key(fold.sequence))?
            .ok_or(Error::WitnessLost("collection pending map selection"))?;
        let address: [u8; 32] = address
            .try_into()
            .map_err(|_| Error::WitnessLost("collection pending map address"))?;
        let pending: map_tree::PersistentMapV1 =
            archive::decode(&self.archive.read_object(&address, 2048)?)?;
        pending.validate()?;
        if pending.root() != fold.lineage.public.pending_outgoing_root {
            return Err(Error::WitnessLost("collection pending map root"));
        }
        let (low, opening) = pending.non_membership(&mut self.archive, credit)?;
        Ok(DerivedOutgoingAbsence { low, opening })
    }

    /// Collect one historical step in bounded restartable turns. A newer durable Ω must cover
    /// it; the current head and latest folded head are always retained. Send collection also
    /// requires authenticated removal from that Ω's retained native pending-outgoing map. Earned fees have
    /// independent custody and are unaffected. Unload/activation/control output records remain
    /// available for their ledger use; only old Receive and acknowledged Send outputs are pruned.
    ///
    /// The source-selected intent and permanent step metadata precede every deletion. A crash
    /// can only require repeating the same idempotent removal, never re-proving or re-signing.
    /// # Errors
    /// Missing coverage, pending outgoing Send, conflicting intent or uncertain storage.
    pub fn collect_retained_step(&mut self, sequence: u128) -> Result<CollectionStatus, Error> {
        let Some(guard) = self.scheduler.start() else {
            return Ok(CollectionStatus::Idle);
        };
        guard.token.check()?;
        let (old, mut manifest) = self.sync_manifest()?;
        if let Some(intent) = manifest.collection.as_ref() {
            if intent.sequence != sequence {
                return Err(Error::Invalid("another collection is pending"));
            }
        } else {
            let folded = manifest
                .folded
                .filter(|folded| *folded > sequence)
                .ok_or(Error::FoldRequired)?;
            if manifest.indexed.is_none_or(|head| sequence >= head) {
                return Err(Error::Invalid("collection current head"));
            }
            let mut entry = self.step_entry(&manifest, sequence)?;
            if entry.collected {
                return Ok(CollectionStatus::Collected(sequence));
            }
            if sequence == 0 {
                let activation = manifest.activation.ok_or(Error::Invalid(
                    "Bootstrap activation originals are not retained",
                ))?;
                self.require_activation_retention(activation, &entry)?;
            }
            let step = self.indexed_step(&manifest, sequence)?;
            let latest = self.indexed_step(&manifest, folded)?;
            let fold = self
                .read_fold_cancellable(&latest, Some(&guard.token))?
                .ok_or(Error::WitnessLost("collection covering Ω"))?;
            if let KagemushaWalletEffectV1::Send { credit_id, fee, .. } =
                step.frozen.capsule.statement.effect
            {
                let opening =
                    self.collection_outgoing_absence(&manifest, &fold.record, &credit_id)?;
                guard.token.check()?;
                valid(kagemusha_wallet_indexed_verify_non_membership_v1(
                    &fold.record.lineage.public.pending_outgoing_root,
                    &credit_id,
                    &opening.low,
                    &opening.opening,
                ))?;
                // Required claim bytes must already be durable before the last Send output is
                // deleted. A finalized payout may instead have authorized their own deletion.
                if fee != 0 {
                    self.require_fee_claim(&manifest, credit_id, &step.retained.record.output)?;
                }
            }
            entry.collected = true;
            manifest.steps = manifest.steps.set(
                &mut self.archive,
                manifest::sequence_key(sequence),
                &archive::encode(&entry)?,
            )?;
            manifest.collection = Some(CollectionIntent {
                sequence,
                covering_sequence: folded,
                covering_fold: manifest
                    .folds
                    .get(&mut self.archive, &manifest::sequence_key(folded))?
                    .ok_or(Error::WitnessLost("collection covering identity"))?
                    .try_into()
                    .map_err(|_| Error::WitnessLost("collection covering identity"))?,
                next_checkpoint: 0,
                phase: 0,
            });
            self.publish_manifest(old, &manifest)?;
            return Ok(CollectionStatus::Progress(sequence));
        }
        let mut intent = manifest
            .collection
            .clone()
            .ok_or(Error::WitnessLost("collection intent"))?;
        let entry = self.step_entry(&manifest, sequence)?;
        if !entry.collected || intent.next_checkpoint > entry.checkpoints || intent.phase > 4 {
            return Err(Error::WitnessLost("collection progress"));
        }
        if intent.covering_sequence <= sequence
            || manifest
                .folded
                .is_none_or(|folded| intent.covering_sequence > folded)
            || manifest
                .folds
                .get(
                    &mut self.archive,
                    &manifest::sequence_key(intent.covering_sequence),
                )?
                .as_deref()
                != Some(intent.covering_fold.as_slice())
        {
            return Err(Error::WitnessLost("collection covering identity"));
        }
        match intent.phase {
            0 if intent.next_checkpoint < entry.checkpoints => {
                self.archive.remove(ArchiveKey::Checkpoint {
                    sequence,
                    ordinal: intent.next_checkpoint,
                })?;
                intent.next_checkpoint += 1;
            }
            0 => {
                self.archive.remove(ArchiveKey::Fold(sequence))?;
                intent.phase = 1;
            }
            1 => {
                self.archive.remove(ArchiveKey::Capsule(entry.capsule))?;
                intent.phase = 2;
            }
            2 => {
                self.custody
                    .collect_capsule(entry.selected_generation, entry.capsule)?;
                intent.phase = 3;
            }
            3 => {
                if matches!(
                    entry.kind,
                    KagemushaWalletOperationKindV1::Send | KagemushaWalletOperationKindV1::Receive
                ) {
                    let tombstone = self
                        .custody
                        .prune_completion(entry.operation, entry.kind.tag())?;
                    if tombstone.operation_id != entry.operation
                        || tombstone.capsule_digest != entry.capsule
                        || tombstone.selected_generation != entry.selected_generation
                        || tombstone.completion_digest != entry.completion
                        || tombstone.kind != entry.kind.tag()
                    {
                        return Err(Error::WitnessLost("collection source tombstone"));
                    }
                }
                intent.phase = 4;
            }
            4 => {
                manifest.collection = None;
                self.publish_manifest(old, &manifest)?;
                return Ok(CollectionStatus::Collected(sequence));
            }
            _ => return Err(Error::WitnessLost("collection phase")),
        }
        manifest.collection = Some(intent);
        self.publish_manifest(old, &manifest)?;
        Ok(CollectionStatus::Progress(sequence))
    }

    /// Resume the exact source-selected collection after a restart, if any.
    /// # Errors
    /// The same custody errors as [`Self::collect_retained_step`].
    pub fn resume_collection(&mut self) -> Result<Option<CollectionStatus>, Error> {
        let (_, manifest) = self.manifest()?;
        manifest
            .collection
            .map(|intent| self.collect_retained_step(intent.sequence))
            .transpose()
    }
}
