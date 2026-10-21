//! Exact Send-bound Archive intake and read-only retry through permanent Native intent DATA.

use super::*;

fn require_bound_payment(
    original: &[u8],
    scheme: &[u8; 32],
    wallet: &[u8; 32],
    commitment: &[u8; 32],
    operation: &[u8; 32],
) -> Result<KagemushaWalletPaymentV1, Error> {
    let payment = read_model_original(
        || KagemushaWalletPaymentV1::decode_canonical(original, scheme),
        Error::Invalid("G1 validation"),
    )?;
    if payment.send.receipt.capsule_commitment != *commitment
        || valid(payment.send.statement.operation_id(wallet))? != *operation
    {
        return Err(Error::WitnessLost("bound Archive Send operation"));
    }
    Ok(payment)
}

fn require_bound_request(
    selected_original: &[u8],
    completed_original: &[u8],
    payment: &KagemushaWalletPaymentV1,
) -> Result<(), Error> {
    // The selected Send retains the receiver's open Request, while its capsule
    // and Archive retain that Request completed for this exact Payment. Complete
    // only the payer fields, preserving every receiver term, original and signature.
    // An already completed selection must be the very same completion.
    let selected: KagemushaWalletRequestV1 = archive::decode(selected_original)?;
    let completed = valid(selected.complete_with(&valid(payment.signed_request())?))?;
    if archive::encode(&completed)? != completed_original {
        return Err(Error::WitnessLost("selected Send original Request"));
    }
    Ok(())
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(super) fn bound_archive_intent(
        &mut self,
        send_request: &[u8; 32],
        credited: &[u8],
    ) -> Result<NativeIntentV1, Error> {
        if *send_request == [0; 32]
            || credited.is_empty()
            || credited.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        {
            return Err(Error::Invalid("bound Credited input"));
        }
        let (_, manifest) = self.manifest()?;
        let send = self
            .preparation_entry(&manifest, send_request)?
            .ok_or(Error::Invalid("unknown selected Send"))?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        let original = self
            .archive
            .read_object(&send.retained_request()?, REQUEST_MAX_BYTES)?;
        let selected = NativeIntentV1::decode(&original, &scheme)?;
        let Some(OperationRequestV1 {
            request_id,
            action: OperationActionV1::Send { request },
        }) = selected.user_request()
        else {
            return Err(Error::Invalid("selected request is not Send"));
        };
        if request_id != send_request || send.capsule.is_some() != send.operation.is_some() {
            return Err(Error::WitnessLost("selected Send mapping"));
        }
        let capsule = send
            .capsule
            .ok_or(Error::Invalid("Send has no selected operation"))?;
        let commitment = send
            .capsule_commitment
            .ok_or(Error::WitnessLost("selected Send commitment"))?;
        let operation = send
            .operation
            .ok_or(Error::WitnessLost("selected Send operation"))?;
        match self.retry_bound_operation(&capsule, &commitment, &operation)? {
            Some(Completion::Complete(_) | Completion::Archived) => {}
            Some(Completion::Pending) => return Err(Error::Pending),
            _ => return Err(Error::WitnessLost("selected Send completion")),
        }
        let archive_id = NativeIntentV1::archive_identity(&capsule, &self.wallet_id, credited);
        // Resolve the permanent private intent before touching collected Send witnesses.
        // Its originals and operation mapping survive Send output/capsule collection.
        let (_, manifest) = self.manifest()?;
        if let Some(entry) = self.preparation_entry(&manifest, &archive_id)? {
            let bytes = if let Some(address) = entry.request {
                Some(
                    crate::kagemusha_wallet_archive_bytes_v1::PrivateArchiveBytes::from_guarded(
                        zeroize::Zeroizing::new(
                            self.archive.read_object(&address, REQUEST_MAX_BYTES)?,
                        ),
                    ),
                )
            } else {
                self.pending_intake_original(archive_id, &entry)?
            };
            if let Some(bytes) = bytes {
                let intent = NativeIntentV1::decode(&bytes, &scheme)?;
                let archive = intent
                    .archive_request()
                    .ok_or(Error::WitnessLost("bound Archive intent kind"))?;
                if intent.request_id() != archive_id
                    || archive.send_capsule != capsule
                    || archive.send_commitment != commitment
                    || archive.credited != credited
                {
                    return Err(Error::WitnessLost("bound Archive originals"));
                }
                let payment = require_bound_payment(
                    &archive.payment,
                    &self.scheme_id,
                    &self.wallet_id,
                    &commitment,
                    &operation,
                )?;
                require_bound_request(request, &archive.request, &payment)?;
                return Ok(intent);
            }
        }
        let evidence: KagemushaWalletCreditedV1 = archive::decode(credited)?;
        valid(evidence.validate())?;
        if evidence.scheme_id != self.scheme_id {
            return Err(Error::Invalid("Credited scheme"));
        }
        let credit = match &evidence.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => {
                let KagemushaWalletEffectV1::Receive { credit_id, .. } = package.statement.effect
                else {
                    return Err(Error::Invalid("Credited Receive kind"));
                };
                credit_id
            }
            KagemushaWalletCreditedEvidenceV1::Status { status } => status.opening.credit_id,
        };
        let (source, certificates) = self.archive_send_source(&credit)?;
        if source.frozen.capsule.custody_digest() != capsule
            || source.frozen.capsule.receipt_commitment() != commitment
            || source.frozen.capsule.body().operation_id != operation
        {
            return Err(Error::Invalid("Credited names another Send"));
        }
        let intent = NativeIntentV1::archive(&source, certificates, credited.to_vec())?;
        if intent.request_id() != archive_id {
            return Err(Error::WitnessLost("bound Archive identity"));
        }
        let archive = intent
            .archive_request()
            .ok_or(Error::WitnessLost("bound Archive intent kind"))?;
        let payment = require_bound_payment(
            &archive.payment,
            &self.scheme_id,
            &self.wallet_id,
            &commitment,
            &operation,
        )?;
        require_bound_request(request, &archive.request, &payment)?;
        Ok(intent)
    }

    /// Read only the exact selected Send's private Archive outcome. Unknown is not delivery;
    /// Preparing/Pending require retry, and COMPLETE is the Archive operation, not Send pruning.
    ///
    /// # Errors
    /// Foreign Send/evidence binding, lost originals, unavailable custody or invalid mappings.
    pub fn credited_status_for_send(
        &mut self,
        send_request: &[u8; 32],
        credited: &[u8],
    ) -> Result<RequestStatusV1, Error> {
        if *send_request == [0; 32]
            || credited.is_empty()
            || credited.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        {
            return Err(Error::Invalid("bound Credited input"));
        }
        let (_, manifest) = self.manifest()?;
        let send = self
            .preparation_entry(&manifest, send_request)?
            .ok_or(Error::Invalid("unknown selected Send"))?;
        if send.kind != KagemushaWalletOperationKindV1::Send {
            return Err(Error::Invalid("selected request is not Send"));
        }
        let capsule = send.capsule.ok_or(Error::Pending)?;
        let archive_id = NativeIntentV1::archive_identity(&capsule, &self.wallet_id, credited);
        if let Some(entry) = self.preparation_entry(&manifest, &archive_id)? {
            if entry.kind != KagemushaWalletOperationKindV1::ArchiveSent {
                return Err(Error::WitnessLost("bound Archive kind"));
            }
            if entry.request.is_none() {
                return Ok(RequestStatusV1::Preparing);
            }
        }
        let intent = self.bound_archive_intent(send_request, credited)?;
        self.retry_request(&intent.request_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_state_v1::tests::fixture;

    #[test]
    fn retained_delivery_payment_requires_exact_send_capsule_operation_and_wallet() {
        // Canonical wire fixture exercises binding only, never installed proof qualification.
        let payment: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");
        let original = payment.to_canonical_bytes().unwrap();
        let wallet = payment
            .signed_request()
            .expect("fixture Request")
            .body
            .payer_wallet_id;
        let scheme = payment.send.statement.scheme_id;
        let capsule = payment.send.receipt.capsule_commitment;
        let operation = payment.send.statement.operation_id(&wallet).unwrap();
        require_bound_payment(&original, &scheme, &wallet, &capsule, &operation).unwrap();
        assert!(require_bound_payment(&original, &scheme, &[9; 32], &capsule, &operation).is_err());
        assert!(require_bound_payment(&original, &scheme, &wallet, &[9; 32], &operation).is_err());
        assert!(require_bound_payment(&original, &scheme, &wallet, &capsule, &[9; 32]).is_err());
        assert!(require_bound_payment(&original, &[9; 32], &wallet, &capsule, &operation).is_err());
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(require_bound_payment(&trailing, &scheme, &wallet, &capsule, &operation).is_err());
    }

    #[test]
    fn exact_archive_identity_is_stable_and_binds_each_original_scope() {
        let capsule = [3; 32];
        let wallet = [4; 32];
        let credited = vec![5; 10];
        let identity = NativeIntentV1::archive_identity(&capsule, &wallet, &credited);
        assert_eq!(
            identity,
            NativeIntentV1::archive_identity(&capsule, &wallet, &credited)
        );
        assert_ne!(
            identity,
            NativeIntentV1::archive_identity(&[6; 32], &wallet, &credited)
        );
        assert_ne!(
            identity,
            NativeIntentV1::archive_identity(&capsule, &[6; 32], &credited)
        );
        assert_ne!(
            identity,
            NativeIntentV1::archive_identity(&capsule, &wallet, &[6; 10])
        );
    }
}

impl<C: Custody, A: ArchiveStore, N: NativePreparation> Coordinator<C, A, N> {
    /// Verify and process exact Credited evidence for one already committed local Send.
    /// Binding is checked before any Archive effect. Retry resolves the original private intent,
    /// including after its Send's witnesses were collected; it never issues another Send.
    ///
    /// # Errors
    /// Invalid evidence/binding, Native proof failure, unavailable custody or ordinary Advance errors.
    pub fn accept_credited_for_send(
        &mut self,
        send_request: &[u8; 32],
        credited: &[u8],
    ) -> Result<Completion, Error> {
        let intent = self.bound_archive_intent(send_request, credited)?;
        self.execute_intent(intent)
    }
}

#[cfg(test)]
impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    pub(in crate::kagemusha_wallet_state_v1) fn retain_delivery_test_preparing(
        &mut self,
        request: NativeIntentV1,
    ) -> Result<(), Error> {
        let (mut selected, mut manifest) = self.manifest()?;
        let bytes = archive::encode(&request)?;
        let mut entry = Entry::bound(&self.scheme_id, &self.wallet_id, &request, &bytes);
        entry.request = Some(self.archive.write_object(&bytes, REQUEST_MAX_BYTES)?);
        self.publish_preparation(&mut selected, &mut manifest, request.request_id(), &entry)
    }

    pub(in crate::kagemusha_wallet_state_v1) fn retain_delivery_test_mapping(
        &mut self,
        request: NativeIntentV1,
        capsule: [u8; 32],
        commitment: [u8; 32],
        operation: [u8; 32],
    ) -> Result<(), Error> {
        let (mut selected, mut manifest) = self.manifest()?;
        let bytes = archive::encode(&request)?;
        let mut entry = Entry::bound(&self.scheme_id, &self.wallet_id, &request, &bytes);
        entry.request = Some(self.archive.write_object(&bytes, REQUEST_MAX_BYTES)?);
        entry.capsule = Some(capsule);
        entry.capsule_commitment = Some(commitment);
        entry.operation = Some(operation);
        self.publish_preparation(&mut selected, &mut manifest, request.request_id(), &entry)
    }
}
