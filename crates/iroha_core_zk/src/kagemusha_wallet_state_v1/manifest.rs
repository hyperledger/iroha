//! Source-selected fixed manifests and bounded recovery of the unindexed committed tail.

use super::*;

#[path = "manifest/blacklists.rs"]
mod blacklists;
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_checkpoint_digest_v1 as manifest_digest;

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::Manifest")]
pub(super) struct Manifest {
    pub scheme_id: [u8; 32],
    pub wallet_id: [u8; 32],
    pub indexed: Option<u128>,
    pub capsule: [u8; 32],
    pub steps: IndexRoot,
    pub credits: IndexRoot,
    pub outgoing: IndexRoot,
    pub folds: IndexRoot,
    pub claims: IndexRoot,
    pub preparations: IndexRoot,
    pub blacklists: IndexRoot,
    pub capsule_plans: IndexRoot,
    pub capsule_sources: IndexRoot,
    pub issued_requests: IndexRoot,
    pub sessions: IndexRoot,
    pub activation: Option<[u8; 32]>,
    pub close_loads: IndexRoot,
    pub ledger_checkpoint: Option<[u8; 32]>,
    pub finality_epochs: IndexRoot,
    pub finality_epoch: Option<u64>,
    pub ledger_retired: Option<[u8; 32]>,
    pub ledger_load_plans: IndexRoot,
    pub ledger_load_ordinals: IndexRoot,
    pub ledger_unload_confirmations: IndexRoot,
    pub ledger_unload_proofs: IndexRoot,
    pub ledger_unload_retired: Option<([u8; 32], [u8; 32])>,
    pub direct_anchors: IndexRoot,
    pub fold_pending: IndexRoot,
    pub folded: Option<u128>,
    pub checkpoint_count: u32,
    pub checkpoint_digest: [u8; 32],
    pub credit_tree: credit_tree::CreditTree,
    pub collection: Option<super::collection::CollectionIntent>,
}
#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::StepEntry")]
pub(super) struct StepEntry {
    pub capsule: [u8; 32],
    pub operation: [u8; 32],
    pub selected_generation: u128,
    pub completion: [u8; 32],
    pub kind: KagemushaWalletOperationKindV1,
    pub checkpoints: u32,
    pub collected: bool,
}
impl Manifest {
    fn empty(scheme_id: [u8; 32], wallet_id: [u8; 32]) -> Self {
        Self {
            scheme_id,
            wallet_id,
            indexed: None,
            capsule: [0; 32],
            steps: IndexRoot::default(),
            credits: IndexRoot::default(),
            outgoing: IndexRoot::default(),
            folds: IndexRoot::default(),
            claims: IndexRoot::default(),
            preparations: IndexRoot::default(),
            blacklists: IndexRoot::default(),
            capsule_plans: IndexRoot::default(),
            capsule_sources: IndexRoot::default(),
            issued_requests: IndexRoot::default(),
            sessions: IndexRoot::default(),
            activation: None,
            close_loads: IndexRoot::default(),
            ledger_checkpoint: None,
            finality_epochs: IndexRoot::default(),
            finality_epoch: None,
            ledger_retired: None,
            ledger_load_plans: IndexRoot::default(),
            ledger_load_ordinals: IndexRoot::default(),
            ledger_unload_confirmations: IndexRoot::default(),
            ledger_unload_proofs: IndexRoot::default(),
            ledger_unload_retired: None,
            direct_anchors: IndexRoot::default(),
            fold_pending: IndexRoot::default(),
            folded: None,
            checkpoint_count: 0,
            checkpoint_digest: [0; 32],
            credit_tree: credit_tree::CreditTree::default(),
            collection: None,
        }
    }
}
pub(super) fn sequence_key(sequence: u128) -> [u8; 32] {
    let mut key = [0; 32];
    key[16..].copy_from_slice(&sequence.to_be_bytes());
    key
}
impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(super) fn manifest(&mut self) -> Result<([u8; 32], Manifest), Error> {
        let Some((digest, bytes)) = self.custody.archive_checkpoint()? else {
            return Ok(([0; 32], Manifest::empty(self.scheme_id, self.wallet_id)));
        };
        if bytes.len()
            > crate::kagemusha_wallet_advance_v1::KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1
            || manifest_digest(&bytes) != digest
        {
            return Err(Error::WitnessLost("archive manifest digest"));
        }
        let manifest: Manifest = archive::decode(&bytes)?;
        if manifest.scheme_id != self.scheme_id
            || manifest.wallet_id != self.wallet_id
            || manifest.indexed.is_none()
            || manifest
                .folded
                .zip(manifest.indexed)
                .is_some_and(|(a, b)| a > b)
            || (manifest.checkpoint_count == 0) != (manifest.checkpoint_digest == [0; 32])
        {
            return Err(Error::WitnessLost("archive manifest binding"));
        }
        Ok((digest, manifest))
    }
    pub(super) fn publish_manifest(
        &mut self,
        expected: [u8; 32],
        manifest: &Manifest,
    ) -> Result<[u8; 32], Error> {
        let bytes = archive::encode(manifest)?;
        let expected_digest = manifest_digest(&bytes);
        if self.custody.publish_archive_checkpoint(expected, &bytes)? != expected_digest {
            return Err(Error::WitnessLost("archive manifest publication"));
        }
        Ok(expected_digest)
    }
    pub(super) fn checked_step(&mut self, digest: [u8; 32]) -> Result<ReleasedStep, Error> {
        let frozen = self.frozen(digest)?;
        let c = &frozen.capsule;
        let Lookup::Retained(retained) = self.custody.lookup(&c.operation_id)? else {
            return Err(Error::WitnessLost("released completion"));
        };
        if retained.operation_id != c.operation_id
            || retained.capsule_digest != digest
            || retained.frame != valid(retained.record.to_canonical_bytes())?
            || retained.completion_digest != valid(retained.record.completion_digest())?
        {
            return Err(Error::WitnessLost("completion binding"));
        }
        valid(retained.record.verify(&frozen.credential, c))?;
        Ok(ReleasedStep {
            frozen,
            retained: *retained,
        })
    }
    pub(super) fn indexed_step(
        &mut self,
        manifest: &Manifest,
        sequence: u128,
    ) -> Result<ReleasedStep, Error> {
        let entry = self.step_entry(manifest, sequence)?;
        if entry.collected {
            return Err(Error::Collected);
        }
        let step = self.checked_step(entry.capsule)?;
        if step.retained.operation_id != entry.operation
            || step.retained.selected_generation != entry.selected_generation
            || step.retained.completion_digest != entry.completion
            || step.frozen.capsule.kind != entry.kind
        {
            return Err(Error::WitnessLost("step metadata"));
        }
        if step.frozen.capsule.statement.sequence != sequence {
            return Err(Error::WitnessLost("indexed sequence"));
        }
        Ok(step)
    }
    pub(super) fn step_entry(
        &mut self,
        manifest: &Manifest,
        sequence: u128,
    ) -> Result<StepEntry, Error> {
        let bytes = manifest
            .steps
            .get(&mut self.archive, &sequence_key(sequence))?
            .ok_or(Error::WitnessLost("step index"))?;
        archive::decode(&bytes)
    }
    /// Recover only the unindexed tail. Each iteration retains one capsule and bounded index
    /// paths; permanent history is never collected into a vector on a payment/fold operation.
    pub(super) fn sync_manifest(&mut self) -> Result<([u8; 32], Manifest), Error> {
        let status = self.status()?;
        let (old, mut manifest) = self.manifest()?;
        let marker = match status {
            SlotStatus::Enrollment(_) => {
                if manifest.indexed.is_some() {
                    return Err(Error::WitnessLost("manifest before bootstrap"));
                }
                return Ok((old, manifest));
            }
            SlotStatus::Released(marker) => marker,
            SlotStatus::Pending(_) => return Err(Error::Pending),
            _ => return Err(Error::NoHead),
        };
        let (sequence, _, mut digest) = marker.head().ok_or(Error::NoHead)?;
        if manifest.indexed.is_some_and(|indexed| indexed > sequence) {
            return Err(Error::WitnessLost("manifest ahead of custody"));
        }
        if manifest.indexed == Some(sequence) {
            if manifest.capsule != digest {
                return Err(Error::WitnessLost("manifest head conflict"));
            }
            return Ok((old, manifest));
        }
        let mut head = match marker.marker().state {
            KagemushaWalletMarkerStateV1::Head { head, .. } => head,
            _ => return Err(Error::NoHead),
        };
        let mut current = sequence;
        loop {
            if manifest.indexed == Some(current) {
                if digest != manifest.capsule {
                    return Err(Error::WitnessLost("indexed boundary"));
                }
                let boundary = self.indexed_step(&manifest, current)?;
                if boundary.frozen.capsule.statement.successor != head {
                    return Err(Error::WitnessLost("indexed boundary head"));
                }
                break;
            }
            let step = self.checked_step(digest)?;
            let c = &step.frozen.capsule;
            if c.statement.sequence != current || c.statement.successor != head {
                return Err(Error::WitnessLost("capsule chain"));
            }
            let entry = StepEntry {
                capsule: digest,
                operation: c.operation_id,
                selected_generation: step.retained.selected_generation,
                completion: step.retained.completion_digest,
                kind: c.kind,
                checkpoints: 0,
                collected: false,
            };
            self.index_source_custody(&mut manifest, digest, c.kind)?;
            manifest.steps = manifest.steps.set(
                &mut self.archive,
                sequence_key(current),
                &archive::encode(&entry)?,
            )?;
            if let KagemushaWalletEffectV1::Send { credit_id, .. } = c.statement.effect {
                if manifest
                    .outgoing
                    .get(&mut self.archive, &credit_id)?
                    .is_some()
                {
                    return Err(Error::WitnessLost("duplicate committed Send"));
                }
                manifest.outgoing =
                    manifest
                        .outgoing
                        .set(&mut self.archive, credit_id, &sequence_key(current))?;
            }
            if let KagemushaWalletEffectV1::Receive {
                credit_id, amount, ..
            } = c.statement.effect
            {
                if manifest
                    .credits
                    .get(&mut self.archive, &credit_id)?
                    .is_some()
                {
                    return Err(Error::WitnessLost("duplicate committed Receive"));
                }
                let entry = ConsumedCredit {
                    payment_digest: c.payment_digest,
                    amount,
                    sequence: current,
                };
                manifest.credits = manifest.credits.set(
                    &mut self.archive,
                    credit_id,
                    &archive::encode(&entry)?,
                )?;
            }
            self.retain_fee_claim(&mut manifest, &step)?;
            self.retain_blacklist_source(&mut manifest, &step)?;
            digest = c.predecessor_capsule_digest;
            head = c.statement.predecessor;
            if current == 0 {
                if digest != [0; 32] || !head.is_zero() || manifest.indexed.is_some() {
                    return Err(Error::WitnessLost("bootstrap boundary"));
                }
                break;
            }
            current -= 1;
        }
        manifest.indexed = Some(sequence);
        manifest.capsule = marker.head().ok_or(Error::NoHead)?.2;
        let published = self.publish_manifest(old, &manifest)?;
        Ok((published, manifest))
    }
    pub(super) fn indexed_credit(
        &mut self,
        manifest: &Manifest,
        id: &[u8; 32],
    ) -> Result<Option<ConsumedCredit>, Error> {
        manifest
            .credits
            .get(&mut self.archive, id)?
            .map(|bytes| archive::decode(&bytes))
            .transpose()
    }
}
