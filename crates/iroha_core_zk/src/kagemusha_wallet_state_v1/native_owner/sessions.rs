//! Durable native open Request setup and the payer companion, without an Advance or a
//! caller-supplied signing body.

use super::*;
use rand::rand_core::TryRngCore as _;

const ACTION_MAX: usize = KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 4096;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::SetupActionV1")]
pub(in crate::kagemusha_wallet_state_v1) enum Action {
    Request {
        amount: u128,
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
        // Retirement stops new receiving quotes. It preserves Send of remaining value: the
        // payer pays another receiver's open Request (§6.3).
        if matches!(action, Action::Request { .. })
            && source.frozen.capsule.body().successor_state.core.lifecycle
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
        issued: Option<&KagemushaWalletRequestV1>,
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
            (Action::Request { .. }, Some(request))
                if request.body.nonce == plan.nonce && archive::encode(request)? == bytes => {}
            _ => return Err(Error::WitnessLost("setup output binding")),
        }
        plan.output = Some(
            self.archive
                .write_object(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?,
        );
        if let Some(request) = issued {
            manifest.issued_requests = super::super::session_custody::retain_request(
                &mut self.archive,
                manifest.issued_requests,
                request,
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
        // This read cannot recreate a missing Request after a head change.
        // Fresh output and its issued Request were selected by the same publication.
        let (_, manifest) = self.manifest()?;
        let selected = manifest
            .issued_requests
            .get(&mut self.archive, &request.request_digest())?
            .ok_or(Error::WitnessLost("setup issued Request custody"))?;
        let record: super::super::preparation_custody::IssuedRequestCustodyV1 =
            archive::decode(&selected)?;
        let (_, retained) = record.read(
            &mut self.archive,
            &self.scheme_id,
            &self.wallet_id,
            &request.request_digest(),
        )?;
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
                    &source.frozen.capsule.body().successor_state,
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

    /// Issue one exact open receiver Request for `amount` from selected local policy: any payer
    /// completes it with its own wallet, account and next ordinal. A nonzero held fee schedule
    /// requires its signed original and issuer. The exact signed Request is durable before any
    /// bytes leave this method.
    ///
    /// # Errors
    /// A zero amount, mismatched fee evidence, unavailable custody or changed unfinished setup
    /// source. Retries return retained bytes and never sign a replacement.
    pub fn request(
        &mut self,
        setup_id: [u8; 32],
        amount: u128,
        fee: Option<&(
            KagemushaWalletFeeScheduleV1,
            KagemushaWalletSignerCertificateV1,
        )>,
    ) -> Result<Vec<u8>, Error> {
        let _payment = self.scheduler.payment();
        if amount == 0 {
            return Err(Error::Invalid("Request amount"));
        }
        let scheme = *self.proofs.installed.verifier().scheme();
        let action = Action::Request {
            amount,
            fee: fee.map(|original| Box::new(*original)),
        };
        let mut plan = self.setup(setup_id, &action)?;
        let bytes = if let Some(output) = plan.output {
            self.archive
                .read_object(&output, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?
        } else {
            let (source, snapshot) = self.setup_source(&plan)?;
            let credential = source.frozen.credential;
            let state = source.frozen.capsule.body().successor_state;
            let certificates = self.setup_certificates(&source, &snapshot)?;
            let issuer = *valid(certificates.certificate(
                &credential.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            ))?;
            valid(credential.verify(&scheme, &issuer))?;
            let (slot, fee_amount, certificates) = match fee {
                None if state.rest.fee_schedule == [0; 32] => (
                    KagemushaWalletFeeScheduleSlotV1::None,
                    0,
                    valid(KagemushaWalletCertificateSetV1::new(vec![issuer]))?,
                ),
                Some(&(schedule, fee_issuer))
                    if schedule.fee_schedule_digest() == state.rest.fee_schedule
                        && schedule.body.asset_digest == state.core.asset_digest =>
                {
                    valid(schedule.verify(&scheme, &fee_issuer))?;
                    (
                        KagemushaWalletFeeScheduleSlotV1::Present { schedule },
                        valid(schedule.fee(amount))?,
                        valid(KagemushaWalletCertificateSetV1::new(vec![
                            issuer, fee_issuer,
                        ]))?,
                    )
                }
                _ => return Err(Error::Invalid("Request selected fee schedule")),
            };
            let body = KagemushaWalletRequestBodyV1 {
                version: 1,
                scheme_id: self.scheme_id,
                asset_digest: state.core.asset_digest,
                payer_wallet_id: [0; 32],
                payer_account_digest: [0; 32],
                receiver_wallet_id: self.wallet_id,
                receiver_account_digest: credential.body.account_digest,
                send_ordinal: 0,
                receiver_credential_digest: credential.credential_digest(),
                amount,
                fee_schedule: state.rest.fee_schedule,
                fee: fee_amount,
                policy_epoch: state.core.policy_epoch,
                scheme_policy: state.rest.scheme_policy,
                receiver_accepted_time_ms: state.core.accepted_time_floor_ms,
                certificates: valid(certificates.digest())?,
                nonce: plan.nonce,
            };
            valid(body.check_request_rule(&credential, &state))?;
            let signature = self.custody.sign_setup(
                plan.source,
                &credential.body.payment_key,
                KagemushaWalletSigningDomainV1::Request,
                &body.transcript(),
            )?;
            let request = valid(KagemushaWalletRequestV1::sign(
                &scheme,
                body,
                credential,
                slot,
                certificates,
                KagemushaWalletSignerOutputV1::Raw(*signature.as_raw_bytes()),
            ))?;
            let bytes = archive::encode(&request)?;
            self.finish_setup(setup_id, &action, &mut plan, &bytes, Some(&request))?;
            bytes
        };
        let request: KagemushaWalletRequestV1 = archive::decode(&bytes)?;
        valid(request.verify_open(&scheme))?;
        if request.body.nonce != plan.nonce
            || request.body.receiver_wallet_id != self.wallet_id
            || request.body.amount != amount
        {
            return Err(Error::WitnessLost("retained Request binding"));
        }
        self.issued_setup_request(&request)
    }

    /// Recover the companion of an exact retained Send from its historical source custody.
    /// Later renewal or head advancement cannot replace the credential that authenticated the
    /// Payment. Receive needs that credential and its issuer beside the Payment (`KWPYPC1`).
    /// Nothing is signed, so a running fold sub-proof keeps proving.
    ///
    /// # Errors
    /// A malformed, foreign or changed Payment, or unavailable retained Send custody or issuer.
    pub fn payment_companion(&mut self, payment_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if payment_bytes.is_empty() || payment_bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(Error::Invalid("Payment input bound"));
        }
        let payment = read_model_original(
            || KagemushaWalletPaymentV1::decode_canonical(payment_bytes, &self.scheme_id),
            Error::Invalid("G1 validation"),
        )?;
        let identity = valid(payment.digests())?;
        let (source, certificates) = self.archive_send_source(&identity.credit_id)?;
        if source.retained.record.output != payment_bytes {
            return Err(Error::WitnessLost(
                "payer companion retained Payment binding",
            ));
        }
        let certificates: KagemushaWalletCertificateSetV1 = archive::decode(&certificates)?;
        let credential = source.frozen.credential;
        let issuer = valid(certificates.certificate(
            &credential.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        ))?;
        let companion = valid(KagemushaWalletPayerCompanionV1::new(credential, issuer))?;
        valid(companion.check_payment(&payment))?;
        valid(companion.to_canonical_bytes())
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
        let action = action_bytes(&Action::Request {
            amount: 7,
            fee: None,
        })
        .unwrap();
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
                &action_bytes(&Action::Request {
                    amount: 8,
                    fee: None
                })
                .unwrap()
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
                amount: u128::MAX,
                fee: None
            })
            .unwrap()
            .len()
                <= ACTION_MAX
        );
    }

    fn setup_quote(source: &FrozenTransition) -> KagemushaWalletRequestV1 {
        let template: KagemushaWalletRecoveryCapsuleV1 =
            fixture("KagemushaWalletRecoveryCapsuleV1");
        let original = template
            .body()
            .retained_inputs
            .iter()
            .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
            .unwrap();
        let mut request: KagemushaWalletRequestV1 = archive::decode(&original.bytes).unwrap();
        let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
        let local = source.credential;
        let state = &source.capsule.body().successor_state;
        let issuer = enrollment_issuer(&local);
        request.receiver_credential = local;
        request.certificates = KagemushaWalletCertificateSetV1::new(vec![issuer]).unwrap();
        request.fee_schedule = KagemushaWalletFeeScheduleSlotV1::None;
        request.body = KagemushaWalletRequestBodyV1 {
            version: 1,
            scheme_id: local.body.scheme_id,
            asset_digest: local.body.asset_digest,
            payer_wallet_id: [0; 32],
            payer_account_digest: [0; 32],
            receiver_wallet_id: local.body.wallet_id,
            receiver_account_digest: local.body.account_digest,
            send_ordinal: 0,
            receiver_credential_digest: local.credential_digest(),
            amount: 7,
            fee_schedule: [0; 32],
            fee: 0,
            policy_epoch: state.core.policy_epoch,
            scheme_policy: state.rest.scheme_policy,
            receiver_accepted_time_ms: state.core.accepted_time_floor_ms,
            certificates: request.certificates.digest().unwrap(),
            nonce: [73; 32],
        };
        let signature: Signature = signer(&local).sign(&request.body.signing_message());
        request.signature = KagemushaDeviceSignatureV1::from_raw_bytes(
            &signature.normalize_s().unwrap_or(signature).to_bytes(),
        )
        .unwrap();
        request.verify_open(&scheme).unwrap();
        request
    }

    #[test]
    fn request_publication_retry_is_exact_after_uncertainty_and_a_new_head() {
        for selected_before_error in [false, true] {
            let mut wallet = wallet();
            let boot = bootstrap();
            wallet.commit(boot.clone()).unwrap();
            let mut request = setup_quote(&boot);
            let source = boot.capsule.custody_digest();
            let id = [74; 32];
            let action = Action::Request {
                amount: 7,
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
                    .finish_setup(id, &action, &mut plan, &original, Some(&request))
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
                    .finish_setup(id, &action, &mut resumed, &original, Some(&request))
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
        let request = setup_quote(&boot);
        let id = [74; 32];
        let action = Action::Request {
            amount: 7,
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
                Some(&request),
            ),
            Err(Error::Invalid(_))
        ));
        assert_eq!(wallet.manifest().unwrap().0, root);
        assert_eq!(wallet.custody.signatures, signatures);
    }
}
