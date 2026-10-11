//! Retained originals and map drafts over the coordinator's one exclusive archive.
//!
//! Reads authenticate the selected state. Updates remain unpublished until the native
//! verifier accepts the successor and Advance selects its capsule. Signed peer objects
//! never supply local clock custody or replace a previously issued Request.

use super::{map_custody::SourceMapsV1, *};

pub(super) const SOURCE_CUSTODY_MAX_BYTES: usize = 32 * 1024;

/// Fixed local original roles. These are not caller-selected storage paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreparationOriginalV1 {
    /// Canonical current credential, bound to the source state's credential digest.
    CurrentCredential,
    /// Canonical certificate set containing the current credential's issuer.
    EnrollmentCertificates,
    /// Held scheme policy, or absence when the state commits zero.
    SchemePolicy,
    /// Held signed blacklist, or absence when the state commits zero.
    Blacklist,
    /// Held signed quota share, or absence when the state commits zero.
    QuotaShare,
    /// Held signed time response; this alone does not establish a direct exchange.
    TimeAnchor,
}

impl PreparationOriginalV1 {
    const ALL: [Self; 6] = [
        Self::CurrentCredential,
        Self::EnrollmentCertificates,
        Self::SchemePolicy,
        Self::Blacklist,
        Self::QuotaShare,
        Self::TimeAnchor,
    ];
    const fn index(self) -> usize {
        match self {
            Self::CurrentCredential => 0,
            Self::EnrollmentCertificates => 1,
            Self::SchemePolicy => 2,
            Self::Blacklist => 3,
            Self::QuotaShare => 4,
            Self::TimeAnchor => 5,
        }
    }
    const fn maximum(self) -> usize {
        match self {
            Self::CurrentCredential => KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
            Self::Blacklist => KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1,
            Self::EnrollmentCertificates => KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
            Self::SchemePolicy => KAGEMUSHA_WALLET_SCHEME_POLICY_MAX_BYTES_V1,
            Self::QuotaShare => KAGEMUSHA_WALLET_QUOTA_SHARE_MAX_BYTES_V1,
            Self::TimeAnchor => KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1,
        }
    }
    fn expected(self, state: &KagemushaWalletStateV1) -> Option<[u8; 32]> {
        match self {
            Self::CurrentCredential => Some(state.core.credential_digest),
            Self::EnrollmentCertificates => None,
            Self::SchemePolicy => Some(state.rest.scheme_policy),
            Self::Blacklist => Some(state.rest.blacklist),
            Self::QuotaShare => Some(state.rest.quota_share),
            Self::TimeAnchor => Some(state.rest.time_anchor),
        }
    }
    fn digest(self, bytes: &[u8], scheme: &[u8; 32]) -> Result<Option<[u8; 32]>, Error> {
        if bytes.is_empty() || bytes.len() > self.maximum() {
            return Err(Error::WitnessLost("retained original bound"));
        }
        Ok(Some(match self {
            Self::CurrentCredential => {
                valid(KagemushaWalletCredentialV1::decode_canonical(bytes, scheme))?
                    .credential_digest()
            }
            Self::EnrollmentCertificates => {
                let set: KagemushaWalletCertificateSetV1 = archive::decode(bytes)?;
                valid(set.validate())?;
                if set.certificates.iter().any(|c| c.body.scheme_id != *scheme) {
                    return Err(Error::WitnessLost("retained certificate scheme"));
                }
                return Ok(None);
            }
            Self::SchemePolicy => valid(KagemushaWalletSchemePolicyV1::decode_canonical(
                bytes, scheme,
            ))?
            .scheme_policy_digest(),
            Self::Blacklist => valid(KagemushaWalletBlacklistV1::decode_canonical(bytes, scheme))?
                .blacklist_digest(),
            Self::QuotaShare => {
                valid(KagemushaWalletQuotaShareV1::decode_canonical(bytes, scheme))?
                    .quota_share_digest()
            }
            Self::TimeAnchor => {
                valid(KagemushaWalletTimeAnchorV1::decode_canonical(bytes, scheme))?
                    .time_anchor_digest()
            }
        }))
    }
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::SourceCustodyV1")]
pub(super) struct SourceCustodyV1 {
    version: u16,
    pub(super) maps: SourceMapsV1,
    originals: [Option<[u8; 32]>; 6],
    blacklist_reference: Option<BlacklistOriginalReferenceV1>,
}

impl SourceCustodyV1 {
    /// Called only by the native enrollment owner after issuer admission.
    pub(super) fn bootstrap(
        store: &mut dyn ObjectStore,
        state: &KagemushaWalletStateV1,
        credential: &[u8],
        certificates: &[u8],
    ) -> Result<Self, Error> {
        let mut value = Self {
            version: 1,
            maps: SourceMapsV1::default(),
            originals: [None; 6],
            blacklist_reference: None,
        };
        value.maps.require(state)?;
        for (role, bytes) in [
            (PreparationOriginalV1::CurrentCredential, credential),
            (PreparationOriginalV1::EnrollmentCertificates, certificates),
        ] {
            role.digest(bytes, &state.core.scheme_id)?;
            value.originals[role.index()] = Some(store.write_object(bytes, role.maximum())?);
        }
        value.require(store, state)?;
        Ok(value)
    }

    // A completed Unload retains its request plan even after historical capsule collection.
    // Read only the two fixed original roles selected by that plan. The retained package
    // binds the credential digest; no caller-selected state or map snapshot is introduced.
    pub(super) fn unload_identity(
        &self,
        store: &mut dyn ObjectStore,
        package: &KagemushaWalletPackageV1,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
    ) -> Result<(KagemushaWalletCredentialV1, KagemushaWalletCertificateSetV1), Error> {
        if self.version != 1
            || package.statement.effect.kind() != KagemushaWalletOperationKindV1::Unload
        {
            return Err(Error::WitnessLost("Unload selected identity role"));
        }
        let mut read = |role: PreparationOriginalV1| {
            let address = self.originals[role.index()]
                .ok_or(Error::WitnessLost("Unload identity original"))?;
            store.read_object(&address, role.maximum())
        };
        let credential = KagemushaWalletCredentialV1::decode_canonical(
            &read(PreparationOriginalV1::CurrentCredential)?,
            scheme,
        )
        .map_err(|_| Error::WitnessLost("Unload credential original"))?;
        if credential.body.wallet_id != *wallet
            || credential.credential_digest() != package.statement.credential_digest
        {
            return Err(Error::WitnessLost("Unload credential binding"));
        }
        let certificates: KagemushaWalletCertificateSetV1 =
            archive::decode(&read(PreparationOriginalV1::EnrollmentCertificates)?)?;
        certificates
            .validate()
            .map_err(|_| Error::WitnessLost("Unload certificate originals"))?;
        certificates
            .certificate(
                &credential.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            )
            .map_err(|_| Error::WitnessLost("Unload issuer original"))?;
        package
            .verify(&credential)
            .map_err(|_| Error::WitnessLost("Unload selected package"))?;
        Ok((credential, certificates))
    }

    pub(super) fn original(
        &self,
        store: &mut dyn ObjectStore,
        state: &KagemushaWalletStateV1,
        role: PreparationOriginalV1,
    ) -> Result<Option<Vec<u8>>, Error> {
        let expected = role.expected(state);
        let address = self.originals[role.index()];
        if expected == Some([0; 32]) {
            return if address.is_none()
                && (role != PreparationOriginalV1::Blacklist || self.blacklist_reference.is_none())
            {
                Ok(None)
            } else {
                Err(Error::WitnessLost("unheld original is populated"))
            };
        }
        let address = address.ok_or(Error::WitnessLost("required original address"))?;
        let bytes = if role == PreparationOriginalV1::Blacklist {
            let reference = self
                .blacklist_reference
                .as_ref()
                .ok_or(Error::WitnessLost("selected blacklist reference"))?;
            if reference.object_key() != address {
                return Err(Error::WitnessLost("selected blacklist CAS address"));
            }
            let bytes = super::policy_custody::read_blacklist_original(
                store,
                reference,
                &state.core.scheme_id,
            )?;
            let list = KagemushaWalletBlacklistV1::decode_canonical(&bytes, &state.core.scheme_id)
                .map_err(|_| Error::WitnessLost("selected blacklist encoding"))?;
            if list.body.list_version != state.core.blacklist_version
                || list.body.entries_root != state.core.blacklist_root
                || list.body.issued_at_ms != state.core.blacklist_issued_at_ms
            {
                return Err(Error::WitnessLost("selected blacklist state header"));
            }
            bytes
        } else {
            store.read_object(&address, role.maximum())?
        };
        if role
            .digest(&bytes, &state.core.scheme_id)
            .map_err(|_| Error::WitnessLost("retained original encoding"))?
            != expected
        {
            return Err(Error::WitnessLost("original state digest"));
        }
        Ok(Some(bytes))
    }

    pub(super) fn require(
        &self,
        store: &mut dyn ObjectStore,
        state: &KagemushaWalletStateV1,
    ) -> Result<(), Error> {
        if self.version != 1 {
            return Err(Error::WitnessLost("source custody version"));
        }
        self.maps.require(state)?;
        self.require_originals(store, state)
    }

    fn require_originals(
        &self,
        store: &mut dyn ObjectStore,
        state: &KagemushaWalletStateV1,
    ) -> Result<(), Error> {
        for role in PreparationOriginalV1::ALL {
            self.original(store, state, role)?;
        }
        let credential: KagemushaWalletCredentialV1 = archive::decode(
            &self
                .original(store, state, PreparationOriginalV1::CurrentCredential)?
                .ok_or(Error::WitnessLost("current credential"))?,
        )?;
        let certificates: KagemushaWalletCertificateSetV1 = archive::decode(
            &self
                .original(store, state, PreparationOriginalV1::EnrollmentCertificates)?
                .ok_or(Error::WitnessLost("current issuer certificates"))?,
        )?;
        if !certificates
            .certificates
            .iter()
            .any(|c| c.certificate_digest() == credential.body.issuer_certificate)
        {
            return Err(Error::WitnessLost("current credential issuer original"));
        }
        state
            .validate_for_credential(&credential)
            .map_err(|_| Error::WitnessLost("retained credential state"))?;
        Ok(())
    }
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::IssuedRequestCustodyV1")]
pub(super) struct IssuedRequestCustodyV1 {
    pub(super) request: [u8; 32],
    pub(super) gap: Option<[u8; 32]>,
}

impl IssuedRequestCustodyV1 {
    pub(super) fn read(
        &self,
        store: &mut dyn ObjectStore,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        digest: &[u8; 32],
    ) -> Result<(KagemushaWalletRequestV1, Vec<u8>), Error> {
        let bytes = store.read_object(&self.request, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
        let request: KagemushaWalletRequestV1 = archive::decode(&bytes)?;
        request
            .validate()
            .map_err(|_| Error::WitnessLost("issued Request encoding or signature"))?;
        if request.request_digest() != *digest
            || request.body.scheme_id != *scheme
            || request.receiver_credential.body.wallet_id != *wallet
        {
            return Err(Error::WitnessLost("issued Request binding"));
        }
        if (request.body.receiver_blacklist_version != 0) != self.gap.is_some() {
            return Err(Error::WitnessLost("issued Request gap presence"));
        }
        Ok((request, bytes))
    }

    pub(super) fn gap(
        &self,
        store: &mut dyn ObjectStore,
        request: &KagemushaWalletRequestV1,
    ) -> Result<Option<KagemushaWalletBlacklistGapOpeningV1>, Error> {
        self.gap
            .map(|address| {
                let bytes = store.read_object(
                    &address,
                    KAGEMUSHA_WALLET_BLACKLIST_GAP_OPENING_TRANSCRIPT_BYTES_V1,
                )?;
                let opening = KagemushaWalletBlacklistGapOpeningV1::from_transcript(&bytes)
                    .map_err(|_| Error::WitnessLost("issued Request gap encoding"))?;
                opening
                    .verify(
                        &request.body.receiver_blacklist_root,
                        &request.body.payer_account_digest,
                    )
                    .map_err(|_| Error::WitnessLost("issued Request gap binding"))?;
                Ok(opening)
            })
            .transpose()
    }
}

// The object-store adapter avoids exposing a second archive or changing IndexRoot's
// bounded generic implementation merely to accept this internally erased store.
struct Store<'a>(&'a mut dyn ObjectStore);
impl ObjectStore for Store<'_> {
    fn read_object(&mut self, key: &[u8; 32], maximum: usize) -> Result<Vec<u8>, Error> {
        self.0.read_object(key, maximum)
    }
    fn write_object(&mut self, bytes: &[u8], maximum: usize) -> Result<[u8; 32], Error> {
        self.0.write_object(bytes, maximum)
    }
}

/// Native preparation's sealed view of source-selected originals and unpublished maps.
/// Every construction is coordinator-owned; neither roots nor archive selection are public.
pub struct PreparationCustodyV1<'a> {
    maps: PreparationMapsV1<'a>,
    source: SourceCustodyV1,
    state: KagemushaWalletStateV1,
    originals: [Option<[u8; 32]>; 6],
    blacklist_reference: Option<BlacklistOriginalReferenceV1>,
    updated: [bool; 6],
    issued: IndexRoot,
    anchors: IndexRoot,
    epochs: IndexRoot,
    refresh: Option<KagemushaWalletPolicyUpdateKindV1>,
}

impl<'a> PreparationCustodyV1<'a> {
    pub(super) fn snapshot(&self) -> SourceCustodyV1 {
        SourceCustodyV1 {
            version: 1,
            maps: self.maps.snapshot(),
            originals: self.originals,
            blacklist_reference: self.blacklist_reference.clone(),
        }
    }
    pub(super) fn new(
        store: &'a mut dyn ObjectStore,
        selected: &SourceCustodyV1,
        state: &KagemushaWalletStateV1,
        kind: KagemushaWalletOperationKindV1,
        refresh: Option<KagemushaWalletPolicyUpdateKindV1>,
        issued: IndexRoot,
        anchors: IndexRoot,
        epochs: IndexRoot,
    ) -> Result<Self, Error> {
        selected.require(store, state)?;
        let maps = PreparationMapsV1::new(store, &selected.maps, state, kind, refresh)?;
        Ok(Self {
            maps,
            source: selected.clone(),
            state: *state,
            originals: selected.originals,
            blacklist_reference: selected.blacklist_reference.clone(),
            updated: [false; 6],
            issued,
            anchors,
            epochs,
            refresh,
        })
    }

    /// Access only this operation's unpublished, source-rooted map draft.
    pub fn maps(&mut self) -> &mut PreparationMapsV1<'a> {
        &mut self.maps
    }

    pub(crate) fn load_finality_reader(
        &mut self,
        genesis: &iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier,
        epoch: u64,
    ) -> Result<iroha_data_model::sumeragi_finality::SumeragiCommitVerifierV1, Error> {
        use iroha_data_model::sumeragi_finality::{
            MAX_COMMIT_CHECKPOINT_BYTES, SumeragiCommitCheckpointV1, SumeragiCommitVerifierV1,
        };
        let checkpoint = if epoch == 0 {
            SumeragiCommitCheckpointV1::from_authenticated_genesis(genesis)
                .map_err(|_| Error::Proof("Load initial epoch authority"))?
        } else {
            let bytes = self
                .epochs
                .get(
                    &mut Store(self.maps.store()),
                    &manifest::sequence_key(u128::from(epoch)),
                )?
                .ok_or(Error::Invalid("Load epoch has not been synchronized"))?;
            let entry: native_owner::epochs::EpochEntry = archive::decode(&bytes)
                .map_err(|_| Error::WitnessLost("Load selected epoch entry"))?;
            let bytes = self
                .maps
                .store()
                .read_object(&entry.checkpoint, MAX_COMMIT_CHECKPOINT_BYTES)?;
            SumeragiCommitCheckpointV1::decode_canonical(&bytes)
                .map_err(|_| Error::WitnessLost("Load selected epoch original"))?
        };
        if checkpoint.selected_epoch().authorization.epoch != epoch {
            return Err(Error::WitnessLost("Load selected epoch identity"));
        }
        // This index is sealed by the coordinator's protected manifest; the certificate's
        // epoch is only a key. No network-provided checkpoint can enter this restore path.
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, genesis)
            .map_err(|_| Error::WitnessLost("Load selected epoch genesis binding"))
    }

    /// Read the exact selected original. Only a state-committed zero means absence.
    ///
    /// # Errors
    /// Missing, corrupt or foreign originals are custody loss; unavailable reads remain errors.
    pub fn original(&mut self, role: PreparationOriginalV1) -> Result<Option<Vec<u8>>, Error> {
        self.source.original(self.maps.store(), &self.state, role)
    }

    /// Retain one successor original for the selected signed Refresh class.
    /// Repeated identical retention is idempotent; conflicting bytes reject. Source reads
    /// continue to return the predecessor originals. Full successor binding is checked at finish.
    ///
    /// # Errors
    /// Wrong update role, malformed bytes, conflicting retention or storage failure.
    pub fn retain_successor_original(
        &mut self,
        role: PreparationOriginalV1,
        bytes: &[u8],
    ) -> Result<(), Error> {
        use KagemushaWalletPolicyUpdateKindV1 as K;
        use PreparationOriginalV1 as R;
        let allowed = matches!(
            (self.refresh, role),
            (
                Some(K::Credential),
                R::CurrentCredential | R::EnrollmentCertificates
            ) | (Some(K::SchemePolicy), R::SchemePolicy)
                | (Some(K::Blacklist), R::Blacklist)
                | (Some(K::QuotaShare), R::QuotaShare)
                | (Some(K::TimeAnchor), R::TimeAnchor)
        );
        if !allowed {
            return Err(Error::Invalid("successor original role"));
        }
        role.digest(bytes, &self.state.core.scheme_id)?;
        let reference = if role == R::Blacklist {
            // The fixed full-list reference and existing CAS key are selected together.
            // Publish and authenticate exact readback before changing this unpublished draft.
            Some(publish_blacklist_original(
                self.maps.store(),
                &self.state.core.scheme_id,
                bytes,
            )?)
        } else {
            None
        };
        let address = if let Some(reference) = reference.as_ref() {
            reference.object_key()
        } else {
            self.maps.store().write_object(bytes, role.maximum())?
        };
        if self.updated[role.index()]
            && (self.originals[role.index()] != Some(address)
                || (role == R::Blacklist && self.blacklist_reference != reference))
        {
            return Err(Error::Invalid("conflicting successor original"));
        }
        if role == R::Blacklist {
            self.blacklist_reference = reference;
        }
        self.originals[role.index()] = Some(address);
        self.updated[role.index()] = true;
        Ok(())
    }

    fn request_record(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<(KagemushaWalletRequestV1, Vec<u8>, IssuedRequestCustodyV1), Error> {
        let value = self
            .issued
            .get(&mut Store(self.maps.store()), digest)?
            .ok_or(Error::WitnessLost("issued Request custody"))?;
        let record: IssuedRequestCustodyV1 = archive::decode(&value)?;
        let (request, bytes) = record.read(
            self.maps.store(),
            &self.state.core.scheme_id,
            &self.state.core.wallet_id,
            digest,
        )?;
        Ok((request, bytes, record))
    }

    /// Recover the exact locally issued Request, never a peer substitute.
    ///
    /// # Errors
    /// Missing/corrupt original or index, foreign identity or storage unavailability.
    pub fn issued_request(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
        Ok(self.request_record(digest)?.1)
    }

    /// Authenticate the saved gap under the Request's recorded root and payer identity.
    ///
    /// # Errors
    /// Required gap absent, malformed transcript, mismatching historical root or unavailable storage.
    pub fn issued_request_gap(
        &mut self,
        digest: &[u8; 32],
    ) -> Result<Option<KagemushaWalletBlacklistGapOpeningV1>, Error> {
        let (request, _, record) = self.request_record(digest)?;
        record.gap(self.maps.store(), &request)
    }

    /// Recover native direct-exchange observations for the exact committed anchor.
    /// A signed TimeAnchor or Refresh by itself never populates this index.
    ///
    /// # Errors
    /// A committed anchor without direct-exchange custody, corrupt binding or storage failure.
    pub fn anchored_time(&mut self) -> Result<Option<KagemushaWalletAnchoredTimeV1>, Error> {
        if self.state.rest.time_anchor == [0; 32] {
            return Ok(None);
        }
        let address = self
            .anchors
            .get(&mut Store(self.maps.store()), &self.state.rest.time_anchor)?
            .ok_or(Error::WitnessLost("direct time exchange"))?;
        let address: [u8; 32] = address
            .try_into()
            .map_err(|_| Error::WitnessLost("direct time address"))?;
        let bytes = self
            .maps
            .store()
            .read_object(&address, KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1 + 1024)?;
        let anchored: KagemushaWalletAnchoredTimeV1 = archive::decode(&bytes)?;
        anchored
            .validate(self.state.core.time_anchor_max_response_ms)
            .map_err(|_| Error::WitnessLost("direct anchor observation"))?;
        if anchored.anchor.time_anchor_digest() != self.state.rest.time_anchor
            || anchored.anchor.body.scheme_id != self.state.core.scheme_id
        {
            return Err(Error::WitnessLost("direct anchor binding"));
        }
        Ok(Some(anchored))
    }

    pub(super) fn finish(
        mut self,
        successor: &KagemushaWalletStateV1,
    ) -> Result<SourceCustodyV1, Error> {
        // Authenticate originals while the one archive borrow is still available.
        let mut value = self.source;
        value.originals = self.originals;
        value.blacklist_reference = self.blacklist_reference;
        // Maps are checked after consuming the draft; original checks use their own roots.
        value.require_originals(self.maps.store(), successor)?;
        value.maps = self.maps.finish(successor)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
