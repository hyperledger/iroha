//! Durable preparation context selected by an exact capsule, never by an in-memory cache.

use super::{
    preparation_custody::{SOURCE_CUSTODY_MAX_BYTES, SourceCustodyV1},
    *,
};

#[derive(Clone)]
pub(super) struct PreparedTransitionV1 {
    pub(super) request: NativeIntentV1,
    pub(super) native: Vec<u8>,
    pub(super) source: [u8; 32],
    pub(super) draft: SourceCustodyV1,
}

/// Exact retained native preparation presented again at the final Advance boundary.
/// Construction and archive selection are private to the coordinator.
/// Bootstrap has no ordinary intent/plan; its native owner separately authenticates
/// generation-zero admission. A production owner rejects an ordinary operation without
/// a matching preparation, including after process restart.
pub struct TransitionCustodyV1<'a> {
    prepared: Option<PreparedTransitionV1>,
    custody: Option<PreparationCustodyV1<'a>>,
}

impl<'a> TransitionCustodyV1<'a> {
    pub(super) fn new(
        prepared: Option<PreparedTransitionV1>,
        custody: Option<PreparationCustodyV1<'a>>,
    ) -> Result<Self, Error> {
        if prepared.is_some() != custody.is_some() {
            return Err(Error::WitnessLost("transition preparation context"));
        }
        Ok(Self { prepared, custody })
    }

    /// Borrow the exact selected request, retained native choices and fresh source draft.
    /// The native owner must rederive the operation and compare the whole frozen capsule.
    pub fn prepared(&mut self) -> Option<(&NativeIntentV1, &[u8], &mut PreparationCustodyV1<'a>)> {
        self.prepared
            .as_ref()
            .zip(self.custody.as_mut())
            .map(|(plan, custody)| (&plan.request, plan.native.as_slice(), custody))
    }

    pub(super) fn finish(
        self,
        successor: &KagemushaWalletStateV1,
    ) -> Result<Option<SourceCustodyV1>, Error> {
        self.prepared
            .zip(self.custody)
            .map(|(plan, custody)| {
                if archive::encode(&plan.draft)? != archive::encode(&custody.snapshot())? {
                    return Err(Error::WitnessLost("transition changed preparation draft"));
                }
                custody.finish(successor)
            })
            .transpose()
    }
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(crate) fn archive_send_source(
        &mut self,
        credit: &[u8; 32],
    ) -> Result<(ReleasedStep, Vec<u8>), Error> {
        let (_, manifest) = self.sync_manifest()?;
        let sequence = manifest
            .outgoing
            .get(&mut self.archive, credit)?
            .ok_or(Error::WitnessLost("Archive Send identity"))?;
        let sequence: [u8; 32] = sequence
            .try_into()
            .map_err(|_| Error::WitnessLost("Archive Send sequence"))?;
        if sequence[..16] != [0; 16] {
            return Err(Error::WitnessLost("Archive Send sequence width"));
        }
        let sequence = u128::from_be_bytes(
            sequence[16..]
                .try_into()
                .map_err(|_| Error::WitnessLost("Archive Send sequence"))?,
        );
        let send = self.indexed_step(&manifest, sequence)?;
        if !matches!(send.frozen.capsule.statement.effect, KagemushaWalletEffectV1::Send { credit_id, .. } if credit_id == *credit)
        {
            return Err(Error::WitnessLost("Archive Send binding"));
        }
        let source = self.source_custody(&manifest, &send)?;
        let certificates = source
            .original(
                &mut self.archive,
                &send.frozen.capsule.successor_state,
                PreparationOriginalV1::EnrollmentCertificates,
            )?
            .ok_or(Error::WitnessLost("Archive historical issuer set"))?;
        Ok((send, certificates))
    }
    pub(super) fn source_custody(
        &mut self,
        manifest: &manifest::Manifest,
        released: &ReleasedStep,
    ) -> Result<SourceCustodyV1, Error> {
        let capsule = valid(released.frozen.capsule.capsule_digest())?;
        let address = manifest
            .capsule_sources
            .get(&mut self.archive, &capsule)?
            .ok_or(Error::WitnessLost("selected capsule source custody"))?;
        let address: [u8; 32] = address
            .try_into()
            .map_err(|_| Error::WitnessLost("source custody address"))?;
        let source: SourceCustodyV1 = archive::decode(
            &self
                .archive
                .read_object(&address, SOURCE_CUSTODY_MAX_BYTES)?,
        )?;
        source.require(&mut self.archive, &released.frozen.capsule.successor_state)?;
        Ok(source)
    }

    pub(super) fn preparation_source_custody(
        &mut self,
        manifest: &manifest::Manifest,
        released: &ReleasedStep,
        kind: KagemushaWalletOperationKindV1,
        folded: Option<&KagemushaWalletFoldRecordV1>,
    ) -> Result<(SourceCustodyV1, KagemushaWalletStateV1), Error> {
        let mut source = self.source_custody(manifest, released)?;
        let mut state = released.frozen.capsule.successor_state;
        if kind.consumes_lineage() {
            let fold = folded.ok_or(Error::FoldRequired)?;
            let expected = fold.lineage.public.pending_outgoing_root;
            if source.maps.pending().root() != expected {
                let address = manifest
                    .fold_pending
                    .get(&mut self.archive, &manifest::sequence_key(fold.sequence))?
                    .ok_or(Error::WitnessLost("lineage pending descriptor"))?;
                let address: [u8; 32] = address
                    .try_into()
                    .map_err(|_| Error::WitnessLost("lineage pending address"))?;
                let pending: map_tree::PersistentMapV1 =
                    archive::decode(&self.archive.read_object(&address, 2048)?)?;
                pending.validate()?;
                if pending.root() != expected {
                    return Err(Error::WitnessLost("lineage pending root"));
                }
                source.maps.replace_pending(pending);
            }
            state.core.pending_outgoing_root = expected;
            source.require(&mut self.archive, &state)?;
        }
        Ok((source, state))
    }

    pub(super) fn retain_source_custody(
        &mut self,
        capsule: [u8; 32],
        source: &SourceCustodyV1,
    ) -> Result<(), Error> {
        let bytes = archive::encode(source)?;
        if bytes.len() > SOURCE_CUSTODY_MAX_BYTES {
            return Err(Error::Invalid("source custody size"));
        }
        self.archive.put(ArchiveKey::SourceCustody(capsule), &bytes)
    }

    pub(super) fn index_source_custody(
        &mut self,
        manifest: &mut manifest::Manifest,
        capsule: [u8; 32],
        kind: KagemushaWalletOperationKindV1,
    ) -> Result<(), Error> {
        let Some(bytes) = self
            .archive
            .get(ArchiveKey::SourceCustody(capsule), SOURCE_CUSTODY_MAX_BYTES)?
        else {
            if kind == KagemushaWalletOperationKindV1::Bootstrap
                || manifest
                    .capsule_plans
                    .get(&mut self.archive, &capsule)?
                    .is_some()
            {
                return Err(Error::WitnessLost("selected preparation source snapshot"));
            }
            // An independently verified frozen operation has no preparation snapshot.
            // It cannot authorize a future preparation without the mandatory snapshot.
            return Ok(());
        };
        let address = self
            .archive
            .write_object(&bytes, SOURCE_CUSTODY_MAX_BYTES)?;
        if let Some(previous) = manifest.capsule_sources.get(&mut self.archive, &capsule)? {
            if previous != address {
                return Err(Error::WitnessLost("changed source custody"));
            }
        }
        manifest.capsule_sources =
            manifest
                .capsule_sources
                .set(&mut self.archive, capsule, &address)?;
        Ok(())
    }
}
