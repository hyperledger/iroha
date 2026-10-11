//! Bounded selected-policy custody survives collection of historical step capsules.

use super::*;
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1 as object_digest;
use crate::kagemusha_wallet_state_v1::policy_custody::{
    BlacklistOriginalReferenceV1, read_blacklist_original,
};

#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::BlacklistSourceEntryV1")]
struct BlacklistSourceEntryV1 {
    version: u16,
    original: BlacklistOriginalReferenceV1,
    certificates_digest: [u8; 32],
    certificates_bytes: u32,
}

fn authenticate(
    scheme: &KagemushaWalletSchemeV1,
    state: &KagemushaWalletStateV1,
    full: &[u8],
    certificates: &[u8],
) -> Result<[u8; 32], Error> {
    state
        .validate()
        .map_err(|_| Error::WitnessLost("blacklist selected state"))?;
    if certificates.is_empty() || certificates.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Error::WitnessLost("blacklist certificates bound"));
    }
    let set: KagemushaWalletCertificateSetV1 = archive::decode(certificates)?;
    set.verify(scheme)
        .map_err(|_| Error::WitnessLost("blacklist certificates authority"))?;
    let list = KagemushaWalletBlacklistV1::decode_canonical(full, &scheme.scheme_id())
        .map_err(|_| Error::WitnessLost("blacklist selected original"))?;
    let certificate = set
        .certificate(
            &list.body.signer_certificate,
            KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        )
        .map_err(|_| Error::WitnessLost("blacklist certificate role"))?;
    list.verify(scheme, certificate)
        .map_err(|_| Error::WitnessLost("blacklist original authority"))?;
    let key = list.blacklist_digest();
    if key == [0; 32]
        || state.rest.blacklist != key
        || state.core.blacklist_version != list.body.list_version
        || state.core.blacklist_root != list.body.entries_root
        || state.core.blacklist_issued_at_ms != list.body.issued_at_ms
    {
        return Err(Error::WitnessLost("blacklist selected state join"));
    }
    Ok(key)
}

impl BlacklistSourceEntryV1 {
    fn read(
        &self,
        objects: &mut impl ObjectStore,
        scheme: &KagemushaWalletSchemeV1,
        state: &KagemushaWalletStateV1,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let maximum = usize::try_from(self.certificates_bytes)
            .map_err(|_| Error::WitnessLost("blacklist certificates length"))?;
        if self.version != 1
            || self.certificates_digest == [0; 32]
            || maximum == 0
            || maximum > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        {
            return Err(Error::WitnessLost("blacklist source entry"));
        }
        let full = read_blacklist_original(objects, &self.original, &scheme.scheme_id())?;
        let certificates = objects.read_object(&self.certificates_digest, maximum)?;
        if certificates.len() != maximum || object_digest(&certificates) != self.certificates_digest
        {
            return Err(Error::WitnessLost("blacklist exact certificates original"));
        }
        authenticate(scheme, state, &full, &certificates)?;
        Ok((full, certificates))
    }
}

fn retain(
    objects: &mut impl ObjectStore,
    selected: IndexRoot,
    scheme: &KagemushaWalletSchemeV1,
    state: &KagemushaWalletStateV1,
    reference: &BlacklistOriginalReferenceV1,
    certificates: &[u8],
) -> Result<IndexRoot, Error> {
    let full = read_blacklist_original(objects, reference, &scheme.scheme_id())?;
    let key = authenticate(scheme, state, &full, certificates)?;
    let certificates_digest = object_digest(certificates);
    if objects.write_object(certificates, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?
        != certificates_digest
    {
        return Err(Error::WitnessLost("blacklist certificates publication"));
    }
    let entry = BlacklistSourceEntryV1 {
        version: 1,
        original: reference.clone(),
        certificates_digest,
        certificates_bytes: u32::try_from(certificates.len())
            .map_err(|_| Error::WitnessLost("blacklist certificates length"))?,
    };
    if entry.read(objects, scheme, state)? != (full, certificates.to_vec()) {
        return Err(Error::WitnessLost("blacklist source readback"));
    }
    let bytes = archive::encode(&entry)?;
    if let Some(existing) = selected.get(objects, &key)? {
        if existing != bytes {
            return Err(Error::WitnessLost("conflicting blacklist source index"));
        }
        return Ok(selected);
    }
    let proposed = selected.set(objects, key, &bytes)?;
    if proposed.get(objects, &key)?.as_deref() != Some(bytes.as_slice()) {
        return Err(Error::WitnessLost("blacklist source index readback"));
    }
    Ok(proposed)
}

fn selected_originals(
    objects: &mut impl ObjectStore,
    selected: IndexRoot,
    scheme: &KagemushaWalletSchemeV1,
    state: &KagemushaWalletStateV1,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
    state
        .validate()
        .map_err(|_| Error::WitnessLost("blacklist selected state"))?;
    if state.rest.blacklist == [0; 32] {
        return Ok(None);
    }
    let bytes = selected
        .get(objects, &state.rest.blacklist)?
        .ok_or(Error::WitnessLost("selected blacklist source index"))?;
    let entry: BlacklistSourceEntryV1 = archive::decode(&bytes)?;
    entry.read(objects, scheme, state).map(Some)
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(super) fn retain_blacklist_source(
        &mut self,
        manifest: &mut Manifest,
        step: &ReleasedStep,
    ) -> Result<(), Error> {
        let capsule = &step.frozen.capsule;
        let KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::Blacklist,
            update,
            ..
        } = capsule.statement.effect
        else {
            return Ok(());
        };
        if capsule.kind != KagemushaWalletOperationKindV1::RefreshPolicy
            || capsule.scheme_id != self.scheme_id
            || capsule.wallet_id != self.wallet_id
            || update != capsule.successor_state.rest.blacklist
        {
            return Err(Error::WitnessLost("blacklist source released join"));
        }
        let original = |role| -> Result<&[u8], Error> {
            let mut inputs = capsule
                .retained_inputs
                .iter()
                .filter(|input| input.role == role);
            let bytes = &inputs
                .next()
                .ok_or(Error::WitnessLost("blacklist source absent"))?
                .bytes;
            if inputs.next().is_some() {
                return Err(Error::WitnessLost("blacklist source inventory"));
            }
            Ok(bytes)
        };
        let reference = BlacklistOriginalReferenceV1::decode_canonical(
            original(KagemushaWalletRetainedInputRoleV1::PolicyUpdate)?,
            &self.scheme_id,
        )?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        if scheme.scheme_id() != self.scheme_id {
            return Err(Error::WitnessLost("blacklist source scheme"));
        }
        manifest.blacklists = retain(
            &mut self.archive,
            manifest.blacklists,
            &scheme,
            &capsule.successor_state,
            &reference,
            original(KagemushaWalletRetainedInputRoleV1::CertificateSet)?,
        )?;
        Ok(())
    }

    /// Restore the current source-selected full blacklist and exact certificate-set original.
    ///
    /// The bounded immutable index survives collection of the Refresh capsule. This is source
    /// custody and issuer authentication; Native still proves every monetary transition.
    /// No foreign head, scheme, wallet, object digest or history-scan selector is accepted.
    ///
    /// # Errors
    /// Pending, missing/corrupt selected objects, unavailable storage and source changes remain
    /// distinct errors. Absence is returned only when the actual current state holds no list.
    pub fn current_blacklist_originals(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, Error> {
        let (digest, manifest) = self.sync_manifest()?;
        let status = self.status()?;
        let SlotStatus::Released(marker) = &status else {
            return Err(if matches!(status, SlotStatus::Pending(_)) {
                Error::Pending
            } else {
                Error::NoHead
            });
        };
        let checkpoint = self
            .custody
            .archive_checkpoint()?
            .ok_or(Error::WitnessLost("blacklist manifest"))?;
        if checkpoint.1.len()
            > crate::kagemusha_wallet_advance_v1::KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1
            || checkpoint.0 != digest
            || manifest_digest(&checkpoint.1) != digest
            || checkpoint.1 != archive::encode(&manifest)?
            || marker.archive_checkpoint() != digest
        {
            return Err(Error::WitnessLost("blacklist selected manifest"));
        }
        let (sequence, operation, capsule_digest) = marker.head().ok_or(Error::NoHead)?;
        if manifest.indexed != Some(sequence) || manifest.capsule != capsule_digest {
            return Err(Error::WitnessLost("blacklist selected index"));
        }
        let current = self.indexed_step(&manifest, sequence)?;
        let head = match marker.marker().state {
            KagemushaWalletMarkerStateV1::Head { head, .. } => head,
            _ => return Err(Error::NoHead),
        };
        if current.frozen.capsule.statement.successor != head
            || current.retained.operation_id != operation
            || marker.selected_generation() != Some(current.retained.selected_generation)
            || marker.completion_digest() != Some(current.retained.completion_digest)
            || marker.payment_key() != &current.frozen.credential.body.payment_key
        {
            return Err(Error::WitnessLost("blacklist selected head"));
        }
        let (scheme, _) = self.proofs.ledger_scope()?;
        if scheme.scheme_id() != self.scheme_id {
            return Err(Error::WitnessLost("blacklist source scheme"));
        }
        let result = selected_originals(
            &mut self.archive,
            manifest.blacklists,
            &scheme,
            &current.frozen.capsule.successor_state,
        )?;
        if self.status()? != status {
            return Err(Error::WitnessLost("blacklist source marker changed"));
        }
        if self.manifest()?.0 != digest
            || self.custody.archive_checkpoint()?.as_ref() != Some(&checkpoint)
        {
            return Err(Error::WitnessLost("blacklist source manifest changed"));
        }
        if self.status()? != status {
            return Err(Error::WitnessLost("blacklist source marker changed"));
        }
        Ok(result)
    }
}

#[cfg(test)]
#[path = "blacklists/tests.rs"]
mod tests;
