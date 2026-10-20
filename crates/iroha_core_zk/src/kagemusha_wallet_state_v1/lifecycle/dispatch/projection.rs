//! Native per-credit evidence, independent of Archive completion and fold progress.

use super::*;

/// Authenticated local credit or peer evidence projected by the Native owner.
/// This display DATA grants no permission to Archive, spend, collect, refund or retarget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditProjectionV1 {
    evidence: u8,
    archive: u8,
    core_pending: bool,
    credit: [u8; 32],
    payment: [u8; 32],
    amount: u128,
    credited: Vec<u8>,
    credited_len: u32,
}
impl CreditProjectionV1 {
    /// Fixed foreign projection: LE16 version, evidence (1 unfolded/2 credited/3 burned),
    /// Archive (0 receiver/1 awaiting fold/2 removed/3 retained/4 verified, not archived),
    /// core-pending byte, three zero bytes, credit, Payment digest, LE128 amount, LE32
    /// original length and exact native Credited original (receiver only). This is not a
    /// wallet wire message.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(92 + self.credited.len());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&[
            self.evidence,
            self.archive,
            u8::from(self.core_pending),
            0,
            0,
            0,
        ]);
        bytes.extend_from_slice(&self.credit);
        bytes.extend_from_slice(&self.payment);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.credited_len.to_le_bytes());
        bytes.extend_from_slice(&self.credited);
        bytes
    }
}

fn evidence_state(credited: &KagemushaWalletCreditedV1) -> u8 {
    match &credited.evidence {
        KagemushaWalletCreditedEvidenceV1::Receive { .. } => 1,
        KagemushaWalletCreditedEvidenceV1::Status { status } => {
            if status.opening.burned {
                3
            } else {
                2
            }
        }
    }
}

fn pending_member(
    map: &map_tree::PersistentMapV1,
    store: &mut impl ObjectStore,
    expected: &KagemushaWalletPendingOutgoingLeafV1,
) -> Result<bool, Error> {
    let (leaf, opening) = map.member_or_low(store, &expected.credit_id)?;
    if leaf.key == expected.credit_id {
        if leaf.value != valid(expected.leaf_value())? {
            return Err(Error::WitnessLost("projection pending descriptor"));
        }
        valid(kagemusha_wallet_indexed_verify_membership_v1(
            &map.root(),
            &leaf,
            &opening,
        ))?;
        Ok(true)
    } else {
        valid(kagemusha_wallet_indexed_verify_non_membership_v1(
            &map.root(),
            &expected.credit_id,
            &leaf,
            &opening,
        ))?;
        Ok(false)
    }
}

fn outgoing_descriptor(
    credit_id: [u8; 32],
    request: &KagemushaWalletRequestV1,
) -> KagemushaWalletPendingOutgoingLeafV1 {
    KagemushaWalletPendingOutgoingLeafV1 {
        credit_id,
        receiver_wallet_id: request.body.receiver_wallet_id,
        send_ordinal: request.body.send_ordinal,
        amount: request.body.amount,
        fee: request.body.fee,
        request_digest: request.request_digest(),
    }
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    /// Membership of the Send's descriptor in the current head's core pending-outgoing map.
    fn core_pending(
        &mut self,
        manifest: &manifest::Manifest,
        sequence: u128,
        descriptor: &KagemushaWalletPendingOutgoingLeafV1,
    ) -> Result<bool, Error> {
        let current = self.indexed_step(manifest, sequence)?;
        let source = self.source_custody(manifest, &current)?;
        pending_member(source.maps.pending(), &mut self.archive, descriptor)
    }

    fn projection_unchanged(
        &mut self,
        snapshot: &Snapshot,
        manifest: [u8; 32],
    ) -> Result<(), Error> {
        if self.snapshot()? != *snapshot || self.manifest()?.0 != manifest {
            return Err(Error::WitnessLost("credit projection source changed"));
        }
        Ok(())
    }

    /// Project a completed Receive by its permanent local request mapping. A covering fold
    /// supplies the first recorded credit's current authenticated burned flag even before
    /// Receive collection, and even while newer local heads remain unfolded.
    /// # Errors
    /// No completed Receive, wrong mapping, unknown/conflicting credit, lost witnesses,
    /// invalid proof or changed source yields no ownership/evidence projection.
    pub fn receive_credit_projection(
        &mut self,
        request_id: &[u8; 32],
    ) -> Result<CreditProjectionV1, Error> {
        let before = self.snapshot()?;
        let (selected, manifest) = self.manifest()?;
        let entry = self
            .preparation_entry(&manifest, request_id)?
            .ok_or(Error::Invalid("unknown Receive request"))?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        let intent = NativeIntentV1::decode(
            &self
                .archive
                .read_object(&entry.retained_request()?, REQUEST_MAX_BYTES)?,
            &scheme,
        )?;
        let Some(OperationRequestV1 {
            request_id: bound,
            action: OperationActionV1::Receive { payment, .. },
        }) = intent.user_request()
        else {
            return Err(Error::Invalid("projection request is not Receive"));
        };
        if bound != request_id {
            return Err(Error::WitnessLost("Receive projection identity"));
        }
        let payment = read_model_original(
            || KagemushaWalletPaymentV1::decode_canonical(payment, &self.scheme_id),
            Error::Invalid("G1 validation"),
        )?;
        let identity = valid(payment.digests())?;
        let credit = self
            .indexed_credit(&manifest, &identity.credit_id)?
            .ok_or(Error::WitnessLost("Receive projection credit"))?;
        if credit.payment_digest != identity.payment
            || credit.amount != valid(payment.signed_request())?.body.amount
        {
            return Err(Error::CreditConflict);
        }
        let step = self.step_entry(&manifest, credit.sequence)?;
        if entry.operation != Some(step.operation)
            || entry.capsule != Some(step.capsule)
            || step.kind != KagemushaWalletOperationKindV1::Receive
        {
            return Err(Error::WitnessLost("Receive projection source mapping"));
        }
        let completion = self.retry_bound_operation(
            &step.capsule,
            &entry
                .capsule_commitment
                .ok_or(Error::WitnessLost("Receive commitment mapping"))?,
            &step.operation,
        )?;
        if completion == Some(Completion::Archived) && !step.collected {
            return Err(Error::WitnessLost("unselected Receive collection"));
        }
        if !matches!(
            completion,
            Some(Completion::Complete(_) | Completion::Archived)
        ) {
            return Err(Error::WitnessLost("Receive projection incomplete"));
        }
        let credited = if manifest
            .folded
            .is_some_and(|folded| folded >= credit.sequence)
        {
            valid(KagemushaWalletCreditedV1::from_status(
                self.credit_status(&identity.credit_id, &identity.payment)?,
            ))?
        } else {
            let Some(Completion::Complete(original)) = completion else {
                return Err(Error::WitnessLost("unfolded Receive output"));
            };
            let package: KagemushaWalletPackageV1 = archive::decode(&original)?;
            if package.receipt.operation_id != step.operation
                || Some(package.receipt.capsule_commitment) != entry.capsule_commitment
                || package.receipt.payment_digest != identity.payment
                || package.statement.sequence != credit.sequence
                || package.statement.scheme_id != self.scheme_id
                || package.statement.effect
                    != (KagemushaWalletEffectV1::Receive {
                        credit_id: identity.credit_id,
                        payer_wallet_id: valid(payment.signed_request())?.body.payer_wallet_id,
                        amount: credit.amount,
                    })
            {
                return Err(Error::WitnessLost("Receive projection receipt"));
            }
            valid(KagemushaWalletCreditedV1::from_receive(package))?
        };
        let bytes = archive::encode(&credited)?;
        if bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(Error::Invalid("Credited projection bound"));
        }
        let credited_len =
            u32::try_from(bytes.len()).map_err(|_| Error::Invalid("Credited projection bound"))?;
        self.projection_unchanged(&before, selected)?;
        Ok(CreditProjectionV1 {
            evidence: evidence_state(&credited),
            archive: 0,
            core_pending: false,
            credit: identity.credit_id,
            payment: identity.payment,
            amount: credit.amount,
            credited: bytes,
            credited_len,
        })
    }

    /// Project evidence anchored by one exact completed Native Archive. An optional newer
    /// Credited original is verified read-only with the same installed verifier; permanent
    /// Archive originals survive Send collection. No second Archive is performed here.
    /// # Errors
    /// Noncompleted/foreign anchor, invalid fresh evidence, unavailable proofs or maps,
    /// changed source and unknown custody never become a positive delivery verdict.
    pub fn delivery_credit_projection(
        &mut self,
        send: &[u8; 32],
        anchor: &[u8],
        newer: &[u8],
    ) -> Result<CreditProjectionV1, Error> {
        let before = self.snapshot()?;
        let intent = self.bound_archive_intent(send, anchor)?;
        let RequestStatusV1::Outcome(Completion::Complete(output)) =
            self.retry_request(&intent.request_id())?
        else {
            return Err(Error::Invalid("delivery anchor is not complete"));
        };
        let (selected, manifest) = self.manifest()?;
        let entry = self
            .preparation_entry(&manifest, &intent.request_id())?
            .ok_or(Error::WitnessLost("delivery anchor mapping"))?;
        let held = intent
            .archive_request()
            .ok_or(Error::WitnessLost("delivery anchor intent"))?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        intent.validate(&scheme)?;
        let request: KagemushaWalletRequestV1 = archive::decode(&held.request)?;
        let payment = read_model_original(
            || KagemushaWalletPaymentV1::decode_canonical(&held.payment, &self.scheme_id),
            Error::Invalid("G1 validation"),
        )?;
        let identity = valid(payment.digests())?;
        let package: KagemushaWalletPackageV1 = archive::decode(&output)?;
        valid(package.validate())?;
        let anchor_original: KagemushaWalletCreditedV1 = archive::decode(anchor)?;
        let KagemushaWalletEffectV1::ArchiveSent {
            credit_id,
            credited,
        } = package.statement.effect
        else {
            return Err(Error::WitnessLost("delivery anchor completion kind"));
        };
        if credit_id != identity.credit_id
            || credited != valid(anchor_original.verify_for(&scheme, &request, &payment))?.0
            || entry.operation != Some(package.receipt.operation_id)
            || entry.capsule_commitment != Some(package.receipt.capsule_commitment)
            || valid(package.statement.operation_id(&self.wallet_id))?
                != package.receipt.operation_id
        {
            return Err(Error::WitnessLost("delivery anchor completion binding"));
        }
        let original = if newer.is_empty() { anchor } else { newer };
        if original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(Error::Invalid("delivery projection bound"));
        }
        let evidence: KagemushaWalletCreditedV1 = archive::decode(original)?;
        self.proofs.verify_credited(&evidence, &request, &payment)?;
        let descriptor = outgoing_descriptor(identity.credit_id, &request);
        let core_pending = self.core_pending(&manifest, before.sequence, &descriptor)?;
        let archive = if let Some(folded) = manifest
            .folded
            .filter(|folded| *folded >= package.statement.sequence)
        {
            let step = self.indexed_step(&manifest, folded)?;
            let fold = self
                .read_fold(&step)?
                .ok_or(Error::WitnessLost("delivery covering fold"))?;
            let address: [u8; 32] = manifest
                .fold_pending
                .get(&mut self.archive, &manifest::sequence_key(folded))?
                .ok_or(Error::WitnessLost("delivery folded pending map"))?
                .try_into()
                .map_err(|_| Error::WitnessLost("delivery folded pending address"))?;
            let pending: map_tree::PersistentMapV1 =
                archive::decode(&self.archive.read_object(&address, 2048)?)?;
            pending.validate()?;
            if pending.root() != fold.record.lineage.public.pending_outgoing_root {
                return Err(Error::WitnessLost("delivery folded pending root"));
            }
            if pending_member(&pending, &mut self.archive, &descriptor)? {
                3
            } else {
                2
            }
        } else {
            1
        };
        self.projection_unchanged(&before, selected)?;
        Ok(CreditProjectionV1 {
            evidence: evidence_state(&evidence),
            archive,
            core_pending,
            credit: identity.credit_id,
            payment: identity.payment,
            amount: request.body.amount,
            credited: Vec::new(),
            credited_len: 0,
        })
    }

    /// Verify exact Credited evidence for one committed local Send before any Archive, with
    /// the same Send binding and installed verifier as Archive and the anchored projection.
    /// It selects, proves and signs nothing and prepares no Archive, so the Send's fold keeps
    /// running and the Archive can follow later with the same original. Like every
    /// projection, its reads may finish an interrupted tail index or restore a redundant
    /// archive copy. A completed Archive of this original is projected through its anchor.
    /// # Errors
    /// Pending custody or Archive, foreign or incomplete Send, invalid evidence or proofs,
    /// unavailable maps, a pruned or lost Archive outcome and changed source never become a
    /// positive delivery verdict.
    pub fn verified_delivery_projection(
        &mut self,
        send: &[u8; 32],
        credited: &[u8],
    ) -> Result<CreditProjectionV1, Error> {
        let before = self.snapshot()?;
        let intent = self.bound_archive_intent(send, credited)?;
        match self.retry_request(&intent.request_id())? {
            RequestStatusV1::Outcome(Completion::Complete(_)) => {
                return self.delivery_credit_projection(send, credited, &[]);
            }
            // An Archive Advance in flight is reconciled by its own retry, never projected.
            RequestStatusV1::Outcome(Completion::Pending) => return Err(Error::Pending),
            RequestStatusV1::Unknown
            | RequestStatusV1::Preparing
            | RequestStatusV1::Outcome(Completion::NotPerformed(_)) => {}
            RequestStatusV1::Outcome(_) => {
                return Err(Error::Invalid("delivery Archive outcome is not retained"));
            }
        }
        let (selected, manifest) = self.manifest()?;
        let held = intent
            .archive_request()
            .ok_or(Error::WitnessLost("delivery intent"))?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        intent.validate(&scheme)?;
        let request: KagemushaWalletRequestV1 = archive::decode(&held.request)?;
        let payment = read_model_original(
            || KagemushaWalletPaymentV1::decode_canonical(&held.payment, &self.scheme_id),
            Error::Invalid("G1 validation"),
        )?;
        let identity = valid(payment.digests())?;
        let evidence: KagemushaWalletCreditedV1 = archive::decode(credited)?;
        self.proofs.verify_credited(&evidence, &request, &payment)?;
        let descriptor = outgoing_descriptor(identity.credit_id, &request);
        let core_pending = self.core_pending(&manifest, before.sequence, &descriptor)?;
        self.projection_unchanged(&before, selected)?;
        Ok(CreditProjectionV1 {
            evidence: evidence_state(&evidence),
            archive: 4,
            core_pending,
            credit: identity.credit_id,
            payment: identity.payment,
            amount: request.body.amount,
            credited: Vec::new(),
            credited_len: 0,
        })
    }
}
