//! Durable native Offer/Request setup, without an Advance or caller-supplied signing body.

use super::*;
use rand::rand_core::TryRngCore as _;

const ACTION_MAX: usize = KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 4096;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::SetupActionV1")]
pub(in crate::kagemusha_wallet_state_v1) enum Action {
    Offer {
        amount: u128,
    },
    Request {
        offer: Vec<u8>,
        fee: Option<
            Box<(
                KagemushaWalletFeeScheduleV1,
                KagemushaWalletSignerCertificateV1,
            )>,
        >,
    },
}
#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::SetupPlanV1")]
pub(in crate::kagemusha_wallet_state_v1) struct Plan {
    pub(in crate::kagemusha_wallet_state_v1) source: [u8; 32],
    action: [u8; 32],
    pub(in crate::kagemusha_wallet_state_v1) nonce: [u8; 32],
    pub(in crate::kagemusha_wallet_state_v1) output: Option<[u8; 32]>,
}
impl Plan {
    fn require(&self) -> Result<(), Error> {
        if self.source == [0; 32]
            || self.action == [0; 32]
            || self.nonce == [0; 32]
            || self.output == Some([0; 32])
        {
            return Err(Error::WitnessLost("setup plan binding"));
        }
        Ok(())
    }
}
fn credited_credit(credited: &KagemushaWalletCreditedV1) -> Result<[u8; 32], Error> {
    match &credited.evidence {
        KagemushaWalletCreditedEvidenceV1::Receive { package } => {
            let KagemushaWalletEffectV1::Receive { credit_id, .. } = package.statement.effect
            else {
                return Err(Error::Invalid("Credited Receive kind"));
            };
            Ok(credit_id)
        }
        KagemushaWalletCreditedEvidenceV1::Status { status } => Ok(status.opening.credit_id),
    }
}

fn nonce() -> Result<[u8; 32], Error> {
    for _ in 0..128 {
        let mut value = [0; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut value)
            .map_err(|_| Error::Invalid("setup entropy unavailable"))?;
        if value != [0; 32] {
            return Ok(value);
        }
    }
    Err(Error::Invalid("setup entropy unavailable"))
}
fn action_bytes(action: &Action) -> Result<Vec<u8>, Error> {
    let bytes = archive::encode(action)?;
    if bytes.len() > ACTION_MAX {
        return Err(Error::Invalid("setup input bound"));
    }
    Ok(bytes)
}
fn read_plan<A: ObjectStore>(
    store: &mut A,
    index: IndexRoot,
    id: &[u8; 32],
    action: &[u8],
) -> Result<Option<Plan>, Error> {
    let Some(value) = index.get(store, id)? else {
        return Ok(None);
    };
    let plan: Plan = archive::decode(&value)?;
    plan.require()?;
    if store.read_object(&plan.action, ACTION_MAX)? != action {
        return Err(Error::OperationConflict);
    }
    Ok(Some(plan))
}
fn retain_plan<A: ObjectStore>(
    store: &mut A,
    index: IndexRoot,
    id: [u8; 32],
    plan: &Plan,
) -> Result<IndexRoot, Error> {
    plan.require()?;
    index.set(store, id, &archive::encode(plan)?)
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(in crate::kagemusha_wallet_state_v1) fn setup(
        &mut self,
        id: [u8; 32],
        action: &Action,
    ) -> Result<Plan, Error> {
        if id == [0; 32] {
            return Err(Error::Invalid("setup identity"));
        }
        let bytes = action_bytes(action)?;
        let (_, prior) = self.manifest()?;
        if let Some(plan) = read_plan(&mut self.archive, prior.sessions, &id, &bytes)? {
            return Ok(plan);
        }
        let (root, mut manifest) = self.sync_manifest()?;
        if let Some(plan) = read_plan(&mut self.archive, manifest.sessions, &id, &bytes)? {
            return Ok(plan);
        }
        let source = self.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
        self.source_custody(&manifest, &source)?;
        // Retirement stops new receiving quotes. It preserves Send of remaining value,
        // whose peer session still starts with an Offer (§6.3).
        if matches!(action, Action::Request { .. })
            && source.frozen.capsule.successor_state.core.lifecycle
                != KagemushaWalletLifecycleV1::Active
        {
            return Err(Error::Invalid("new Request requires active wallet"));
        }
        let plan = Plan {
            source: manifest.capsule,
            action: self.archive.write_object(&bytes, ACTION_MAX)?,
            nonce: nonce()?,
            output: None,
        };
        manifest.sessions = retain_plan(&mut self.archive, manifest.sessions, id, &plan)?;
        self.publish_manifest(root, &manifest)?;
        Ok(plan)
    }
    fn setup_source(
        &mut self,
        plan: &Plan,
    ) -> Result<
        (
            ReleasedStep,
            super::super::preparation_custody::SourceCustodyV1,
        ),
        Error,
    > {
        let (_, manifest) = self.sync_manifest()?;
        if manifest.capsule != plan.source {
            return Err(Error::Invalid("unfinished setup source changed"));
        }
        let source = self.indexed_step(&manifest, manifest.indexed.ok_or(Error::NoHead)?)?;
        let snapshot = self.source_custody(&manifest, &source)?;
        Ok((source, snapshot))
    }
    pub(in crate::kagemusha_wallet_state_v1) fn finish_setup(
        &mut self,
        id: [u8; 32],
        action: &Action,
        plan: &mut Plan,
        bytes: &[u8],
        issued: Option<(
            &KagemushaWalletRequestV1,
            Option<&KagemushaWalletBlacklistGapOpeningV1>,
        )>,
    ) -> Result<(), Error> {
        let (root, mut manifest) = self.sync_manifest()?;
        if manifest.capsule != plan.source {
            return Err(Error::Invalid("setup changed before publication"));
        }
        let current = read_plan(
            &mut self.archive,
            manifest.sessions,
            &id,
            &action_bytes(action)?,
        )?
        .ok_or(Error::WitnessLost("selected setup plan"))?;
        if current.source != plan.source || current.nonce != plan.nonce || current.output.is_some()
        {
            return Err(Error::WitnessLost("changed setup plan"));
        }
        match (action, issued) {
            (Action::Request { .. }, Some((request, _)))
                if request.body.nonce == plan.nonce && archive::encode(request)? == bytes => {}
            (Action::Offer { .. }, None) => {}
            _ => return Err(Error::WitnessLost("setup output binding")),
        }
        plan.output = Some(
            self.archive
                .write_object(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?,
        );
        if let Some((request, gap)) = issued {
            manifest.issued_requests = super::super::session_custody::retain_request(
                &mut self.archive,
                manifest.issued_requests,
                request,
                gap,
            )?;
        }
        manifest.sessions = retain_plan(&mut self.archive, manifest.sessions, id, plan)?;
        self.publish_manifest(root, &manifest)?;
        Ok(())
    }
    pub(in crate::kagemusha_wallet_state_v1) fn issued_setup_request(
        &mut self,
        request: &KagemushaWalletRequestV1,
    ) -> Result<Vec<u8>, Error> {
        // This read cannot recreate a missing recorded decision after a head change.
        // Fresh output and its issued Request/gap were selected by the same publication.
        let (_, manifest) = self.manifest()?;
        let selected = manifest
            .issued_requests
            .get(&mut self.archive, &request.request_digest())?
            .ok_or(Error::WitnessLost("setup issued Request custody"))?;
        let record: super::super::preparation_custody::IssuedRequestCustodyV1 =
            archive::decode(&selected)?;
        let (original, retained) = record.read(
            &mut self.archive,
            &self.scheme_id,
            &self.wallet_id,
            &request.request_digest(),
        )?;
        record.gap(&mut self.archive, &original)?;
        if retained != archive::encode(request)? {
            return Err(Error::WitnessLost("setup Request original"));
        }
        Ok(retained)
    }

    fn setup_certificates(
        &mut self,
        source: &ReleasedStep,
        snapshot: &super::super::preparation_custody::SourceCustodyV1,
    ) -> Result<KagemushaWalletCertificateSetV1, Error> {
        archive::decode(
            &snapshot
                .original(
                    &mut self.archive,
                    &source.frozen.capsule.successor_state,
                    PreparationOriginalV1::EnrollmentCertificates,
                )?
                .ok_or(Error::WitnessLost("setup issuer original"))?,
        )
    }
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Verify incoming delivery evidence and derive its private Archive intent from the
    /// permanent local Send index. No caller supplies an Archive selector, pending path,
    /// historical credential or Payment. Exact replay retains the original native intent.
    ///
    /// # Errors
    /// Malformed, foreign or unverifiable evidence, unknown local Send, unavailable custody
    /// or artifacts, and the ordinary preparation/Advance errors.
    pub fn accept_credited(&mut self, bytes: &[u8]) -> Result<Completion, Error> {
        if bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(Error::Invalid("Credited input bound"));
        }
        let credited: KagemushaWalletCreditedV1 = archive::decode(bytes)?;
        valid(credited.validate())?;
        if credited.scheme_id != self.scheme_id {
            return Err(Error::Invalid("Credited scheme"));
        }
        let credit = credited_credit(&credited)?;
        self.archive_credited(&credit, bytes.to_vec())
    }

    /// Sign and durably retain a native Offer for the selected Active or Retiring head.
    /// The caller identity is a retry key, never a signing message or monetary authority.
    ///
    /// # Errors
    /// Unavailable custody, invalid amount, reused identity with different input, or lost
    /// selected bytes. An unfinished setup whose source changed must use a new identity.
    pub fn offer(&mut self, setup_id: [u8; 32], amount: u128) -> Result<Vec<u8>, Error> {
        let _payment = self.scheduler.payment();
        if amount == 0 {
            return Err(Error::Invalid("Offer amount"));
        }
        let action = Action::Offer { amount };
        let mut plan = self.setup(setup_id, &action)?;
        let scheme = self.proofs.installed.verifier().scheme().clone();
        if let Some(output) = plan.output {
            let bytes = self
                .archive
                .read_object(&output, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
            let offer: KagemushaWalletOfferV1 = archive::decode(&bytes)?;
            valid(offer.verify(&scheme))?;
            if offer.body.session_nonce != plan.nonce
                || offer.body.amount != amount
                || offer.body.payer_wallet_id != self.wallet_id
            {
                return Err(Error::WitnessLost("retained Offer binding"));
            }
            return Ok(bytes);
        }
        let (source, snapshot) = self.setup_source(&plan)?;
        let credential = source.frozen.credential;
        let certificates = self.setup_certificates(&source, &snapshot)?;
        let issuer = valid(certificates.certificate(
            &credential.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        ))?;
        valid(credential.verify(&scheme, issuer))?;
        let body = KagemushaWalletOfferBodyV1 {
            version: 1,
            scheme_id: self.scheme_id,
            asset_digest: credential.body.asset_digest,
            payer_wallet_id: self.wallet_id,
            payer_credential_digest: credential.credential_digest(),
            next_send: source.frozen.capsule.successor_state.core.next_send,
            amount,
            session_nonce: plan.nonce,
        };
        valid(body.validate())?;
        let signature = self.custody.sign_setup(
            plan.source,
            &credential.body.payment_key,
            KagemushaWalletSigningDomainV1::Offer,
            &body.transcript(),
        )?;
        let offer = valid(KagemushaWalletOfferV1::sign(
            body,
            credential,
            issuer,
            KagemushaWalletSignerOutputV1::Raw(*signature.as_raw_bytes()),
        ))?;
        valid(offer.verify(&scheme))?;
        let bytes = archive::encode(&offer)?;
        self.finish_setup(setup_id, &action, &mut plan, &bytes, None)?;
        Ok(bytes)
    }

    /// Authenticate an Offer and issue one exact receiver Request from selected local policy.
    /// A nonzero held fee schedule requires its signed original and issuer. The exact signed
    /// Request and recorded blacklist gap are durable before any bytes leave this method.
    ///
    /// # Errors
    /// Invalid Offer, mismatched fee evidence, blocked payer, unavailable custody or changed
    /// unfinished setup source. Retries return retained bytes and never sign a replacement.
    pub fn request(
        &mut self,
        setup_id: [u8; 32],
        offer_bytes: &[u8],
        fee: Option<(
            KagemushaWalletFeeScheduleV1,
            KagemushaWalletSignerCertificateV1,
        )>,
    ) -> Result<Vec<u8>, Error> {
        let _payment = self.scheduler.payment();
        if offer_bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(Error::Invalid("Offer bound"));
        }
        let scheme = self.proofs.installed.verifier().scheme().clone();
        let offer: KagemushaWalletOfferV1 = archive::decode(offer_bytes)?;
        valid(offer.verify(&scheme))?;
        let action = Action::Request {
            offer: offer_bytes.to_vec(),
            fee: fee.map(Box::new),
        };
        let mut plan = self.setup(setup_id, &action)?;
        let bytes = if let Some(output) = plan.output {
            self.archive
                .read_object(&output, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?
        } else {
            let (source, snapshot) = self.setup_source(&plan)?;
            let credential = source.frozen.credential;
            let state = source.frozen.capsule.successor_state;
            let certificates = self.setup_certificates(&source, &snapshot)?;
            let issuer = *valid(certificates.certificate(
                &credential.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            ))?;
            valid(credential.verify(&scheme, &issuer))?;
            if credential.body.payment_key == offer.payer_credential.body.payment_key {
                return Err(Error::Invalid("self Request key"));
            }
            let (slot, fee_amount, certificates) = match fee {
                None if state.rest.fee_schedule == [0; 32] => (
                    KagemushaWalletFeeScheduleSlotV1::None,
                    0,
                    valid(KagemushaWalletCertificateSetV1::new(vec![issuer]))?,
                ),
                Some((schedule, fee_issuer))
                    if schedule.fee_schedule_digest() == state.rest.fee_schedule
                        && schedule.body.asset_digest == state.core.asset_digest =>
                {
                    valid(schedule.verify(&scheme, &fee_issuer))?;
                    let amount = valid(schedule.fee(offer.body.amount))?;
                    (
                        KagemushaWalletFeeScheduleSlotV1::Present { schedule },
                        amount,
                        valid(KagemushaWalletCertificateSetV1::new(vec![
                            issuer, fee_issuer,
                        ]))?,
                    )
                }
                _ => return Err(Error::Invalid("Request selected fee schedule")),
            };
            let (blacklist_version, blacklist_root) = state.request_blacklist_decision();
            let body = KagemushaWalletRequestBodyV1 {
                version: 1,
                scheme_id: self.scheme_id,
                asset_digest: state.core.asset_digest,
                payer_wallet_id: offer.payer_credential.body.wallet_id,
                payer_account_digest: offer.payer_credential.body.account_digest,
                receiver_wallet_id: self.wallet_id,
                receiver_account_digest: credential.body.account_digest,
                send_ordinal: offer.body.next_send,
                receiver_credential_digest: credential.credential_digest(),
                amount: offer.body.amount,
                fee_schedule: state.rest.fee_schedule,
                fee: fee_amount,
                policy_epoch: state.core.policy_epoch,
                scheme_policy: state.rest.scheme_policy,
                receiver_accepted_time_ms: state.core.accepted_time_floor_ms,
                receiver_blacklist_version: blacklist_version,
                receiver_blacklist_root: blacklist_root,
                certificates: valid(certificates.digest())?,
                nonce: plan.nonce,
            };
            let blacklist = snapshot
                .original(&mut self.archive, &state, PreparationOriginalV1::Blacklist)?
                .map(|bytes| archive::decode::<KagemushaWalletBlacklistV1>(&bytes))
                .transpose()?;
            let gap = valid(body.check_request_rule(
                &scheme,
                &offer,
                &credential,
                &state,
                blacklist.as_ref(),
            ))?;
            let signature = self.custody.sign_setup(
                plan.source,
                &credential.body.payment_key,
                KagemushaWalletSigningDomainV1::Request,
                &body.transcript(),
            )?;
            let request = valid(KagemushaWalletRequestV1::sign(
                &scheme,
                &offer,
                body,
                credential,
                slot,
                certificates,
                KagemushaWalletSignerOutputV1::Raw(*signature.as_raw_bytes()),
            ))?;
            let bytes = archive::encode(&request)?;
            self.finish_setup(
                setup_id,
                &action,
                &mut plan,
                &bytes,
                Some((&request, gap.as_ref())),
            )?;
            bytes
        };
        let request: KagemushaWalletRequestV1 = archive::decode(&bytes)?;
        valid(request.verify(&scheme))?;
        if request.body.nonce != plan.nonce
            || request.body.receiver_wallet_id != self.wallet_id
            || request.body.send_ordinal != offer.body.next_send
            || request.body.amount != offer.body.amount
            || request.body.payer_wallet_id != offer.payer_credential.body.wallet_id
            || request.body.payer_account_digest != offer.payer_credential.body.account_digest
        {
            return Err(Error::WitnessLost("retained Request binding"));
        }
        self.issued_setup_request(&request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_state_v1::tests::{
        MemoryArchive, bootstrap, enrollment_issuer, field, fixture, frozen, signer, wallet,
    };
    use p256::ecdsa::{Signature, signature::Signer as _};
    #[test]
    fn setup_index_retains_exact_choices_and_rejects_changed_input_or_lost_original() {
        let mut store = MemoryArchive::new();
        let action = action_bytes(&Action::Offer { amount: 7 }).unwrap();
        let id = [4; 32];
        let plan = Plan {
            source: [1; 32],
            action: store.write_object(&action, ACTION_MAX).unwrap(),
            nonce: [2; 32],
            output: None,
        };
        let root = retain_plan(&mut store, IndexRoot::default(), id, &plan).unwrap();
        let restored = read_plan(&mut store, root, &id, &action).unwrap().unwrap();
        assert_eq!(restored.source, plan.source);
        assert_eq!(restored.nonce, plan.nonce);
        assert_eq!(restored.output, None);
        assert!(matches!(
            read_plan(
                &mut store,
                root,
                &id,
                &action_bytes(&Action::Offer { amount: 8 }).unwrap()
            ),
            Err(Error::OperationConflict)
        ));
        assert!(
            read_plan(&mut store, root, &[5; 32], &action)
                .unwrap()
                .is_none()
        );
        let mut changed = restored;
        changed.action = [99; 32];
        let bad = retain_plan(&mut store, root, id, &changed).unwrap();
        assert!(read_plan(&mut store, bad, &id, &action).is_err());
        assert!(read_plan(&mut store, root, &id, &action).is_ok());
    }
    #[test]
    fn setup_plan_rejects_unbound_values_and_keeps_exact_output_reference() {
        let mut plan = Plan {
            source: [1; 32],
            action: [2; 32],
            nonce: [3; 32],
            output: Some([4; 32]),
        };
        plan.require().unwrap();
        let restored: Plan = archive::decode(&archive::encode(&plan).unwrap()).unwrap();
        assert_eq!(restored.output, plan.output);
        plan.nonce = [0; 32];
        assert!(plan.require().is_err());
        plan.nonce = [3; 32];
        plan.output = Some([0; 32]);
        assert!(plan.require().is_err());
    }
    #[test]
    fn setup_nonce_is_nonzero_and_action_is_bounded() {
        assert_ne!(nonce().unwrap(), [0; 32]);
        assert!(
            action_bytes(&Action::Request {
                offer: vec![0; ACTION_MAX + 1],
                fee: None
            })
            .is_err()
        );
    }

    fn setup_quote(
        source: &FrozenTransition,
    ) -> (KagemushaWalletOfferV1, KagemushaWalletRequestV1) {
        let template: KagemushaWalletRecoveryCapsuleV1 =
            fixture("KagemushaWalletRecoveryCapsuleV1");
        let original = template
            .retained_inputs
            .iter()
            .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
            .unwrap();
        let mut request: KagemushaWalletRequestV1 = archive::decode(&original.bytes).unwrap();
        let remote = request.receiver_credential;
        let issuer = *request
            .certificates
            .certificate(
                &remote.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            )
            .unwrap();
        let body = KagemushaWalletOfferBodyV1 {
            version: 1,
            scheme_id: remote.body.scheme_id,
            asset_digest: remote.body.asset_digest,
            payer_wallet_id: remote.body.wallet_id,
            payer_credential_digest: remote.credential_digest(),
            next_send: 0,
            amount: 7,
            session_nonce: [72; 32],
        };
        fn sign(
            credential: &KagemushaWalletCredentialV1,
            message: &[u8],
        ) -> KagemushaDeviceSignatureV1 {
            let signature: Signature = signer(credential).sign(message);
            KagemushaDeviceSignatureV1::from_raw_bytes(
                &signature.normalize_s().unwrap_or(signature).to_bytes(),
            )
            .unwrap()
        }
        let offer = KagemushaWalletOfferV1 {
            body,
            payer_credential: remote,
            certificates: KagemushaWalletCertificateSetV1::new(vec![issuer]).unwrap(),
            signature: sign(&remote, &body.signing_message()),
        };
        let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
        offer.verify(&scheme).unwrap();
        let local = source.credential;
        let state = &source.capsule.successor_state;
        let issuer = enrollment_issuer(&local);
        request.receiver_credential = local;
        request.certificates = KagemushaWalletCertificateSetV1::new(vec![issuer]).unwrap();
        request.fee_schedule = KagemushaWalletFeeScheduleSlotV1::None;
        request.body = KagemushaWalletRequestBodyV1 {
            version: 1,
            scheme_id: local.body.scheme_id,
            asset_digest: local.body.asset_digest,
            payer_wallet_id: remote.body.wallet_id,
            payer_account_digest: remote.body.account_digest,
            receiver_wallet_id: local.body.wallet_id,
            receiver_account_digest: local.body.account_digest,
            send_ordinal: offer.body.next_send,
            receiver_credential_digest: local.credential_digest(),
            amount: offer.body.amount,
            fee_schedule: [0; 32],
            fee: 0,
            policy_epoch: state.core.policy_epoch,
            scheme_policy: state.rest.scheme_policy,
            receiver_accepted_time_ms: state.core.accepted_time_floor_ms,
            receiver_blacklist_version: 0,
            receiver_blacklist_root: [0; 32],
            certificates: request.certificates.digest().unwrap(),
            nonce: [73; 32],
        };
        request.signature = sign(&local, &request.body.signing_message());
        request.verify(&scheme).unwrap();
        (offer, request)
    }

    #[test]
    fn request_publication_retry_is_exact_after_uncertainty_and_a_new_head() {
        for selected_before_error in [false, true] {
            let mut wallet = wallet();
            let boot = bootstrap();
            wallet.commit(boot.clone()).unwrap();
            let (offer, mut request) = setup_quote(&boot);
            let source = boot.capsule.capsule_digest().unwrap();
            let id = [74; 32];
            let action = Action::Request {
                offer: archive::encode(&offer).unwrap(),
                fee: None,
            };
            let mut plan = wallet.setup(id, &action).unwrap();
            assert_eq!(plan.source, source);
            request.body.nonce = plan.nonce;
            let signature: Signature =
                signer(&request.receiver_credential).sign(&request.body.signing_message());
            request.signature = KagemushaDeviceSignatureV1::from_raw_bytes(
                &signature.normalize_s().unwrap_or(signature).to_bytes(),
            )
            .unwrap();
            let original = archive::encode(&request).unwrap();
            let signatures = wallet.custody.signatures;
            wallet.custody.fail_publication = Some(selected_before_error);
            assert!(
                wallet
                    .finish_setup(id, &action, &mut plan, &original, Some((&request, None)))
                    .is_err()
            );
            let (_, manifest) = wallet.manifest().unwrap();
            assert_eq!(
                manifest
                    .issued_requests
                    .get(&mut wallet.archive, &request.request_digest())
                    .unwrap()
                    .is_some(),
                selected_before_error
            );
            assert_eq!(
                read_plan(
                    &mut wallet.archive,
                    manifest.sessions,
                    &id,
                    &action_bytes(&action).unwrap(),
                )
                .unwrap()
                .unwrap()
                .output
                .is_some(),
                selected_before_error,
                "output and issued Request become selected together",
            );
            let mut wallet = Coordinator::new(
                wallet.custody,
                wallet.archive,
                wallet.proofs,
                wallet.scheme_id,
                wallet.wallet_id,
            )
            .unwrap();
            let mut resumed = wallet.setup(id, &action).unwrap();
            assert_eq!(resumed.nonce, plan.nonce);
            if resumed.output.is_none() {
                wallet
                    .finish_setup(id, &action, &mut resumed, &original, Some((&request, None)))
                    .unwrap();
            }
            assert_eq!(wallet.issued_setup_request(&request).unwrap(), original);
            assert_eq!(wallet.custody.signatures, signatures);
            let load = frozen(
                Some(&boot),
                KagemushaWalletEffectV1::Load {
                    receipt_digest: field(90),
                    load_ordinal: 0,
                    amount: 1,
                    online_charge: 0,
                },
            );
            wallet.commit(load).unwrap();
            let replay = wallet.setup(id, &action).unwrap();
            assert_eq!(replay.source, source);
            assert_eq!(replay.nonce, resumed.nonce);
            assert_eq!(
                wallet
                    .archive
                    .read_object(
                        &replay.output.unwrap(),
                        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
                    )
                    .unwrap(),
                original,
            );
            assert_eq!(wallet.issued_setup_request(&request).unwrap(), original);
            // A missing selected original cannot be reconstructed from transport input.
            let (_, manifest) = wallet.manifest().unwrap();
            let record: super::super::super::preparation_custody::IssuedRequestCustodyV1 =
                archive::decode(
                    &manifest
                        .issued_requests
                        .get(&mut wallet.archive, &request.request_digest())
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
            wallet
                .archive
                .remove(ArchiveKey::Object(record.request))
                .unwrap();
            assert!(matches!(
                wallet.issued_setup_request(&request),
                Err(Error::WitnessLost(_))
            ));
        }
    }

    #[test]
    fn a_new_request_cannot_be_published_from_a_different_selected_head() {
        let mut wallet = wallet();
        let boot = bootstrap();
        wallet.commit(boot.clone()).unwrap();
        let (offer, request) = setup_quote(&boot);
        let id = [74; 32];
        let action = Action::Request {
            offer: archive::encode(&offer).unwrap(),
            fee: None,
        };
        let mut plan = wallet.setup(id, &action).unwrap();
        wallet
            .commit(frozen(
                Some(&boot),
                KagemushaWalletEffectV1::Load {
                    receipt_digest: field(90),
                    load_ordinal: 0,
                    amount: 1,
                    online_charge: 0,
                },
            ))
            .unwrap();
        let (root, _) = wallet.manifest().unwrap();
        let signatures = wallet.custody.signatures;
        assert!(matches!(wallet.setup_source(&plan), Err(Error::Invalid(_))));
        assert!(matches!(
            wallet.finish_setup(
                id,
                &action,
                &mut plan,
                &archive::encode(&request).unwrap(),
                Some((&request, None)),
            ),
            Err(Error::Invalid(_))
        ));
        assert_eq!(wallet.manifest().unwrap().0, root);
        assert_eq!(wallet.custody.signatures, signatures);
    }
}
