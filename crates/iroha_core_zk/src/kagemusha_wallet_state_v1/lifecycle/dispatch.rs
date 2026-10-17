//! Source-bound native preparation and exact retry through the existing custody owner.

use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1 as digest;

use super::super::preparation_custody::SourceCustodyV1;
use super::super::transition_custody::PreparedTransitionV1;
use super::*;
pub(super) mod intake;
mod unload;

mod delivery;
mod projection;
pub use projection::CreditProjectionV1;

use super::super::capacity::{FROZEN_BOUND, PLAN_BOUND};

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::PreparationPlanV1")]
struct Plan {
    version: u16,
    scheme: [u8; 32],
    wallet: [u8; 32],
    request_id: [u8; 32],
    kind: KagemushaWalletOperationKindV1,
    request: [u8; 32],
    source: [u8; 32],
    native: PrivateArchiveBytes,
    request_object: [u8; 32],
    draft: SourceCustodyV1,
}

impl Plan {
    fn require(
        &self,
        scheme: &[u8; 32],
        wallet: &[u8; 32],
        request: &NativeIntentV1,
        original: &[u8],
    ) -> Result<(), Error> {
        if self.version != 1
            || self.scheme != *scheme
            || self.wallet != *wallet
            || self.request_id != request.request_id()
            || self.kind != request.kind()
            || self.request != digest("wallet-preparation-request", original)
            || self.source == [0; 32]
            || self.request_object == [0; 32]
            || self.native.is_empty()
            || self.native.len() > PREPARATION_MAX_BYTES
        {
            return Err(Error::WitnessLost("native preparation binding"));
        }
        Ok(())
    }
}

fn original(
    frozen: &FrozenTransition,
    role: KagemushaWalletRetainedInputRoleV1,
    bytes: &[u8],
) -> bool {
    let mut inputs = frozen
        .capsule
        .body()
        .retained_inputs
        .iter()
        .filter(|input| input.role == role);
    inputs.next().is_some_and(|input| input.bytes == bytes) && inputs.next().is_none()
}

fn policy_original(
    body: &KagemushaWalletRecoveryBodyV1,
    kind: KagemushaWalletPolicyUpdateKindV1,
    complete: &[u8],
) -> bool {
    let mut inputs = body
        .retained_inputs
        .iter()
        .filter(|input| input.role == KagemushaWalletRetainedInputRoleV1::PolicyUpdate);
    let Some(input) = inputs.next() else {
        return false;
    };
    inputs.next().is_none()
        && super::super::verify_policy_update_original(
            kind,
            &body.scheme_id,
            &input.bytes,
            complete,
        )
        .is_ok()
}

fn require_frozen(
    request: &NativeIntentV1,
    source: &[u8; 32],
    frozen: &FrozenTransition,
) -> Result<(), Error> {
    use KagemushaWalletRetainedInputRoleV1 as R;
    frozen.validate()?;
    let capsule = &frozen.capsule;
    if capsule.body().kind != request.kind() || capsule.body().predecessor_capsule_digest != *source
    {
        return Err(Error::Invalid("prepared capsule identity"));
    }
    let matches = if let Some(archive) = request.archive_request() {
        original(frozen, R::Request, &archive.request)
            && original(frozen, R::Payment, &archive.payment)
            && original(frozen, R::Credential, &archive.credential)
            && original(frozen, R::CertificateSet, &archive.certificates)
            && original(frozen, R::Credited, &archive.credited)
    } else {
        match &request
            .user_request()
            .ok_or(Error::Invalid("native intent kind"))?
            .action
        {
            OperationActionV1::Load { receipt, finality } => {
                original(frozen, R::LoadReceipt, receipt)
                    && original(frozen, R::LoadFinality, finality)
            }
            OperationActionV1::Send { request } => original(frozen, R::Request, request),
            OperationActionV1::Receive {
                payment,
                payer_credential,
                certificates,
            } => {
                original(frozen, R::Payment, payment)
                    && original(frozen, R::Credential, payer_credential)
                    && original(frozen, R::CertificateSet, certificates)
            }
            OperationActionV1::Refresh {
                kind,
                update,
                certificates,
            } => {
                policy_original(frozen.capsule.body(), *kind, update)
                    && original(frozen, R::CertificateSet, certificates)
                    && matches!(capsule.body().statement.effect, KagemushaWalletEffectV1::RefreshPolicy { update_kind: actual, .. } if actual == *kind)
            }
            OperationActionV1::Unload { amount, charge } => {
                let quote = charge
                    .as_ref()
                    .map(|charge| {
                        KagemushaWalletChargeQuoteV1::decode_canonical(
                            &charge.quote,
                            &capsule.body().scheme_id,
                        )
                        .map(|quote| quote.charge_quote_digest())
                    })
                    .transpose()
                    .map_err(|_| Error::Invalid("prepared charge quote"))?;
                matches!(capsule.body().statement.effect, KagemushaWalletEffectV1::Unload { amount: actual, charge_quote, .. }
                if actual == *amount && charge_quote == quote.unwrap_or([0; 32]))
            }
            OperationActionV1::Retire => {
                capsule.body().statement.effect == KagemushaWalletEffectV1::Retiring
            }
        }
    };
    if !matches {
        return Err(Error::Invalid("prepared request originals"));
    }
    Ok(())
}

#[derive(norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::PreparationEntryV1")]
struct Entry {
    binding: [u8; 32],
    kind: KagemushaWalletOperationKindV1,
    // Bound explicitly owes no original; a selected plan always retains one.
    request: Option<[u8; 32]>,
    plan: Option<[u8; 32]>,
    capsule: Option<[u8; 32]>,
    capsule_commitment: Option<[u8; 32]>,
    operation: Option<[u8; 32]>,
}

impl Entry {
    fn require_binding(&self) -> Result<(), Error> {
        if self.binding == [0; 32]
            || ((self.plan.is_some() || self.capsule.is_some()) && self.request.is_none())
            || self.capsule.is_some() != self.operation.is_some()
            || self.capsule.is_some() != self.capsule_commitment.is_some()
            || self.capsule == Some([0; 32])
            || self.capsule_commitment == Some([0; 32])
            || self.operation == Some([0; 32])
        {
            return Err(Error::WitnessLost("preparation private/public binding"));
        }
        Ok(())
    }
}

/// One native derivation with the exact in-call inputs it was made from. It lives only
/// inside one `execute_intent` call: no clone, codec, coordinator field or review holds it.
struct CallDerivationV1<P> {
    native: P,
    binding: DerivationBindingV1,
}

// Request bytes (through the fixed Entry binding), source, plan choices and draft are this
// call's values. The archive checkpoint transitively binds every custody root and the
// archive-indexed head, so a fresh checkpoint digest is the one value re-read before proving.
#[derive(PartialEq, Eq)]
struct DerivationBindingV1 {
    request: [u8; 32],
    source: [u8; 32],
    checkpoint: [u8; 32],
    plan: [u8; 32],
    draft: [u8; 32],
}

impl DerivationBindingV1 {
    fn new(
        request: [u8; 32],
        source: [u8; 32],
        checkpoint: [u8; 32],
        plan: &Plan,
    ) -> Result<Self, Error> {
        Ok(Self::of(
            request,
            source,
            checkpoint,
            &plan.native,
            &archive::encode(&plan.draft)?,
        ))
    }

    fn of(
        request: [u8; 32],
        source: [u8; 32],
        checkpoint: [u8; 32],
        native: &[u8],
        draft: &[u8],
    ) -> Self {
        use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1 as object;
        Self {
            request,
            source,
            checkpoint,
            plan: object(native),
            draft: object(draft),
        }
    }
}

impl<C: Custody, A: ArchiveStore, N: NativeProofs> Coordinator<C, A, N> {
    fn preparation_entry(
        &mut self,
        manifest: &manifest::Manifest,
        request_id: &[u8; 32],
    ) -> Result<Option<Entry>, Error> {
        manifest
            .preparations
            .get(&mut self.archive, request_id)?
            .map(|bytes| {
                let entry: Entry = archive::decode(&bytes)?;
                entry.require_binding()?;
                Ok(entry)
            })
            .transpose()
    }

    fn publish_preparation(
        &mut self,
        selected: &mut [u8; 32],
        manifest: &mut manifest::Manifest,
        request_id: [u8; 32],
        entry: &Entry,
    ) -> Result<(), Error> {
        entry.require_binding()?;
        manifest.preparations =
            manifest
                .preparations
                .set(&mut self.archive, request_id, &archive::encode(entry)?)?;
        *selected = self.publish_manifest(*selected, manifest)?;
        Ok(())
    }

    pub(in crate::kagemusha_wallet_state_v1) fn transition_preparation(
        &mut self,
        manifest: &manifest::Manifest,
        frozen: &FrozenTransition,
    ) -> Result<Option<PreparedTransitionV1>, Error> {
        let capsule = frozen.capsule.custody_digest();
        let Some(address) = manifest.capsule_plans.get(&mut self.archive, &capsule)? else {
            return Ok(None);
        };
        let address: [u8; 32] = address
            .try_into()
            .map_err(|_| Error::WitnessLost("capsule plan address"))?;
        let plan: Plan = archive::decode(&self.archive.read_object(&address, PLAN_BOUND)?)?;
        let original = self
            .archive
            .read_object(&plan.request_object, REQUEST_MAX_BYTES)?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        let request = NativeIntentV1::decode(&original, &scheme)?;
        plan.require(&self.scheme_id, &self.wallet_id, &request, &original)?;
        require_frozen(&request, &plan.source, frozen)?;
        let entry = self
            .preparation_entry(manifest, &request.request_id())?
            .ok_or(Error::WitnessLost("capsule request mapping"))?;
        if entry.request != Some(plan.request_object)
            || entry.plan != Some(address)
            || entry.capsule != Some(capsule)
            || entry.capsule_commitment != Some(frozen.capsule.receipt_commitment())
            || entry.operation != Some(frozen.capsule.body().operation_id)
        {
            return Err(Error::WitnessLost("capsule plan mapping"));
        }
        Ok(Some(PreparedTransitionV1 {
            request,
            native: std::sync::Arc::new(plan.native),
            source: plan.source,
            draft: plan.draft,
        }))
    }

    // The permanent source-selected Entry binds both identities from one validated W.
    // Retained output and tombstones must still name that exact private custody object.
    fn retry_bound_operation(
        &mut self,
        capsule: &[u8; 32],
        commitment: &[u8; 32],
        operation: &[u8; 32],
    ) -> Result<Option<Completion>, Error> {
        Ok(match self.custody.lookup(operation)? {
            Lookup::Retained(retained) => {
                if retained.operation_id != *operation
                    || retained.capsule_digest != *capsule
                    || retained.record.operation_id != *operation
                    || retained.record.wallet_id != self.wallet_id
                    || retained.record.capsule_digest != *capsule
                    || retained.record.receipt.capsule_commitment != *commitment
                {
                    return Err(Error::WitnessLost(
                        "prepared retained private/public binding",
                    ));
                }
                Some(Completion::Complete(retained.record.output))
            }
            Lookup::Archived(tombstone) => {
                if tombstone.operation_id != *operation || tombstone.capsule_digest != *capsule {
                    return Err(Error::WitnessLost("prepared tombstone binding"));
                }
                Some(Completion::Archived)
            }
            Lookup::SelectedUnsigned { capsule_digest } => {
                if capsule_digest != *capsule {
                    return Err(Error::WitnessLost("prepared selected binding"));
                }
                Some(Completion::Pending)
            }
            Lookup::DeliveryDataLoss => Some(Completion::DeliveryDataLoss),
            Lookup::Unknown => None,
        })
    }

    /// Replay through the permanent credit index after old Receive output collection.
    /// The exact original request and source-selected operation/capsule mapping must agree
    /// with the first consumed credit; the latest covering native Ω supplies fresh evidence.
    fn retry_prepared_intent(
        &mut self,
        request: &NativeIntentV1,
        capsule: &[u8; 32],
        commitment: &[u8; 32],
        operation: &[u8; 32],
    ) -> Result<Option<Completion>, Error> {
        let completion = self.retry_bound_operation(capsule, commitment, operation)?;
        if completion != Some(Completion::Archived) {
            return Ok(completion);
        }
        let Some(OperationActionV1::Receive { payment, .. }) =
            request.user_request().map(|request| &request.action)
        else {
            return Ok(completion);
        };
        let payment = read_model_original(
            || KagemushaWalletPaymentV1::decode_canonical(payment, &self.scheme_id),
            Error::Invalid("G1 validation"),
        )?;
        let identity = valid(payment.digests())?;
        let (_, manifest) = self.sync_manifest()?;
        let credit = self
            .indexed_credit(&manifest, &identity.credit_id)?
            .ok_or(Error::WitnessLost("archived Receive credit"))?;
        if credit.payment_digest != identity.payment
            || credit.amount != valid(payment.signed_request())?.body.amount
        {
            return Err(Error::CreditConflict);
        }
        let step = self.step_entry(&manifest, credit.sequence)?;
        if step.operation != *operation
            || step.capsule != *capsule
            || step.kind != KagemushaWalletOperationKindV1::Receive
            || !step.collected
        {
            return Err(Error::WitnessLost("archived Receive request mapping"));
        }
        let status = self.credit_status(&identity.credit_id, &identity.payment)?;
        Ok(Some(Completion::CreditStatus(archive::encode(&status)?)))
    }

    #[cfg(test)]
    pub(in crate::kagemusha_wallet_state_v1) fn retain_collected_receive_test_request(
        &mut self,
        request: OperationRequestV1,
        frozen: &FrozenTransition,
    ) -> Result<(), Error> {
        // Explicit simulator-only mapping: test proofs/custody cannot install a Native owner.
        let request = NativeIntentV1::user(request);
        require_frozen(
            &request,
            &frozen.capsule.body().predecessor_capsule_digest,
            frozen,
        )?;
        let (mut selected, mut manifest) = self.manifest()?;
        let bytes = archive::encode(&request)?;
        let mut entry = Entry::bound(&self.scheme_id, &self.wallet_id, &request, &bytes);
        entry.request = Some(self.archive.write_object(&bytes, REQUEST_MAX_BYTES)?);
        entry.capsule = Some(frozen.capsule.custody_digest());
        entry.capsule_commitment = Some(frozen.capsule.receipt_commitment());
        entry.operation = Some(frozen.capsule.body().operation_id);
        self.publish_preparation(&mut selected, &mut manifest, request.request_id(), &entry)
    }

    // Projection uses this mapping only after authenticating the selected source manifest.
    // It grants no completion: the caller must re-read the actual custody record/capsule.
    pub(in crate::kagemusha_wallet_state_v1) fn prepared_output_mapping(
        &mut self,
        request_id: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], KagemushaWalletOperationKindV1), Error> {
        if *request_id == [0; 32] {
            return Err(Error::Invalid("output request identity"));
        }
        let (_, manifest) = self.manifest()?;
        let entry = self
            .preparation_entry(&manifest, request_id)?
            .ok_or(Error::Invalid("unknown output request"))?;
        entry.operation.ok_or(Error::Pending)?;
        let original = self
            .archive
            .read_object(&entry.retained_request()?, REQUEST_MAX_BYTES)?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        let request = NativeIntentV1::decode(&original, &scheme)?;
        if request.request_id() != *request_id
            || entry.capsule.is_some() != entry.operation.is_some()
        {
            return Err(Error::WitnessLost("output request mapping"));
        }
        Ok((
            entry.operation.ok_or(Error::Pending)?,
            entry.capsule.ok_or(Error::Pending)?,
            request.kind(),
        ))
    }

    /// Resolve a local request identity through its source-selected actual operation mapping.
    /// An uncommitted preparation has no completion, even when its native plan is durable.
    ///
    /// # Errors
    /// Missing source-bound objects, corrupt mapping or unavailable custody never mean absence.
    pub fn retry_request(&mut self, request_id: &[u8; 32]) -> Result<RequestStatusV1, Error> {
        if *request_id == [0; 32] {
            return Err(Error::Invalid("lifecycle request identity"));
        }
        // The selected manifest remains authoritative while Advance is Pending.
        // Tail synchronization requires Released and would hide the exact operation lookup.
        let (_, manifest) = self.manifest()?;
        let Some(entry) = self.preparation_entry(&manifest, request_id)? else {
            return Ok(RequestStatusV1::Unknown);
        };
        if entry.request.is_none() {
            return Ok(RequestStatusV1::Preparing);
        }
        let original = self
            .archive
            .read_object(&entry.retained_request()?, REQUEST_MAX_BYTES)?;
        let (scheme, _) = self.proofs.ledger_scope()?;
        let request = NativeIntentV1::decode(&original, &scheme)?;
        if request.request_id() != *request_id {
            return Err(Error::WitnessLost("lifecycle request key"));
        }
        if entry.capsule.is_some() != entry.operation.is_some() {
            return Err(Error::WitnessLost("prepared operation mapping"));
        }
        match entry.operation {
            Some(operation) => Ok(self
                .retry_prepared_intent(
                    &request,
                    &entry
                        .capsule
                        .ok_or(Error::WitnessLost("prepared capsule"))?,
                    &entry
                        .capsule_commitment
                        .ok_or(Error::WitnessLost("prepared commitment"))?,
                    &operation,
                )?
                .map_or(RequestStatusV1::Preparing, RequestStatusV1::Outcome)),
            None => Ok(RequestStatusV1::Preparing),
        }
    }
}

impl<C: Custody, A: ArchiveStore, N: NativePreparation> Coordinator<C, A, N> {
    /// Execute typed intent through the same installed native preparation/proof owner.
    ///
    /// The caller holds exclusive wallet custody for this whole call. The existing
    /// source-selected manifest binds each request, plan and prepared capsule before the next
    /// phase starts. Restart reuses original choices and resolves the actual statement-derived
    /// operation identity before proving. One native derivation per call is reused through
    /// proving: the fresh plan's, a recovered batch's replay or a held plan's validation on
    /// fresh custody. Commit derives again independently before Advance. No preparation
    /// record grants completion authority.
    /// Permanent request mappings and pending plans are excluded from proof collection.
    ///
    /// # Errors
    /// Conflicting request, missing native custody, unavailable storage/artifacts, invalid proof
    /// or uncertain Advance. A stale prepared source returns NotPerformed without rebasing.
    pub fn execute(&mut self, request: OperationRequestV1) -> Result<Completion, Error> {
        self.execute_intent(NativeIntentV1::user(request))
    }

    pub(crate) fn archive_credited(
        &mut self,
        credit: &[u8; 32],
        credited: Vec<u8>,
    ) -> Result<Completion, Error> {
        if credited.is_empty() || credited.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(Error::Invalid("Archive evidence size"));
        }
        let (send, certificates) = self.archive_send_source(credit)?;
        self.execute_intent(NativeIntentV1::archive(&send, certificates, credited)?)
    }

    fn execute_intent(&mut self, request: NativeIntentV1) -> Result<Completion, Error> {
        let _payment = self.scheduler.payment();
        let (scheme, _) = self.proofs.ledger_scope()?;
        request.validate(&scheme)?;
        if norito::canonical_frame_len(&request)
            .map_err(|_| Error::Invalid("private intake encoding"))?
            > REQUEST_MAX_BYTES
        {
            return Err(Error::Invalid("lifecycle request size"));
        }
        let bytes = crate::kagemusha_wallet_archive_bytes_v1::PrivateArchiveBytes::encode(&request)
            .map_err(|_| Error::Invalid("private intake encoding"))?;
        if bytes.len() > REQUEST_MAX_BYTES {
            return Err(Error::Invalid("lifecycle request size"));
        }
        // Resolve the source-selected request before requiring a Released head: Advance may
        // already have irreversibly selected this operation and still owe its receipt.
        let (_, selected_manifest) = self.manifest()?;
        if let Some(entry) = self.preparation_entry(&selected_manifest, &request.request_id())? {
            entry.require_request(
                &mut self.archive,
                &self.scheme_id,
                &self.wallet_id,
                &request,
                &bytes,
            )?;
            if entry.capsule.is_some() != entry.operation.is_some() {
                return Err(Error::WitnessLost("prepared operation mapping"));
            }
            if let Some(operation) = entry.operation {
                if let Some(completion) = self.retry_prepared_intent(
                    &request,
                    &entry
                        .capsule
                        .ok_or(Error::WitnessLost("prepared capsule"))?,
                    &entry
                        .capsule_commitment
                        .ok_or(Error::WitnessLost("prepared commitment"))?,
                    &operation,
                )? {
                    return Ok(completion);
                }
            }
        }
        let (mut selected, mut manifest) = self.sync_manifest()?;
        if request.kind() == KagemushaWalletOperationKindV1::Load {
            self.require_ledger_activation(&manifest)?;
        }
        // This dispatcher starts from an enrolled/released wallet. Enrollment is a separate
        // pre-wallet owner; no preparation may manufacture a Bootstrap source.
        let sequence = manifest.indexed.ok_or(Error::NoHead)?;
        let mut entry = if let Some(entry) =
            self.preparation_entry(&manifest, &request.request_id())?
        {
            entry.require_request(
                &mut self.archive,
                &self.scheme_id,
                &self.wallet_id,
                &request,
                &bytes,
            )?;
            entry
        } else {
            let entry = Entry::bound(&self.scheme_id, &self.wallet_id, &request, &bytes);
            self.publish_preparation(&mut selected, &mut manifest, request.request_id(), &entry)?;
            entry
        };
        // Completion lookup precedes source selection/proof work. A mapping's absence from
        // authenticated storage is a custody failure, never permission for a second debit.
        if entry.capsule.is_some() != entry.operation.is_some() {
            return Err(Error::WitnessLost("prepared operation mapping"));
        }
        if let Some(operation) = entry.operation {
            if let Some(completion) = self.retry_prepared_intent(
                &request,
                &entry
                    .capsule
                    .ok_or(Error::WitnessLost("prepared capsule"))?,
                &entry
                    .capsule_commitment
                    .ok_or(Error::WitnessLost("prepared commitment"))?,
                &operation,
            )? {
                return Ok(completion);
            }
        }
        let released = self.indexed_step(&manifest, sequence)?;
        let source_digest = released.frozen.capsule.custody_digest();
        let held_plan = entry
            .plan
            .map(|plan| archive::decode::<Plan>(&self.archive.read_object(&plan, PLAN_BOUND)?))
            .transpose()?;
        if let Some(plan) = &held_plan {
            plan.require(&self.scheme_id, &self.wallet_id, &request, &bytes)?;
            if plan.source != source_digest {
                return Ok(Completion::NotPerformed(NotPerformed::StaleHead));
            }
        }
        let folded = self.read_fold(&released)?.map(|fold| fold.record);
        if request.kind().consumes_lineage() && folded.is_none() {
            return Err(Error::FoldRequired);
        }
        let source = PreparationSourceV1 {
            released: &released,
            folded: folded.as_ref(),
        };
        let (snapshot, map_state) =
            self.preparation_source_custody(&manifest, &released, request.kind(), folded.as_ref())?;
        let refresh = request.refresh();
        let (plan, planned) = if let Some(plan) = held_plan {
            (plan, None)
        } else {
            let Some((plan, prepared)) = self.prepare_intake_plan(
                &request,
                &bytes,
                &source,
                &snapshot,
                &map_state,
                &mut entry,
                &mut selected,
                &mut manifest,
            )?
            else {
                return Ok(Completion::NotPerformed(NotPerformed::StaleHead));
            };
            (plan, Some(prepared))
        };
        plan.require(&self.scheme_id, &self.wallet_id, &request, &bytes)?;
        if Some(plan.request_object) != entry.request {
            return Err(Error::WitnessLost("preparation request original"));
        }
        if plan.source != source_digest {
            return Ok(Completion::NotPerformed(NotPerformed::StaleHead));
        }
        let prepared = if let Some(prepared) = planned {
            // Intake derived this plan once in this call, from fresh choices or by replaying
            // a recovered batch. That one derivation is reused through proving.
            prepared
        } else {
            // A held plan (restart or retry) validates once on fresh custody. Every derivation
            // gets a fresh source draft; replay must never insert twice.
            let mut readonly =
                super::super::object_workspace::ReadOnlyWorkspace::new(&mut self.archive);
            let mut custody = PreparationCustodyV1::new(
                &mut readonly,
                &snapshot,
                &map_state,
                request.kind(),
                refresh,
                manifest.issued_requests,
                manifest.direct_anchors,
                manifest.finality_epochs,
            )?;
            let prepared =
                self.proofs
                    .validate_preparation(&request, &source, &mut custody, &plan.native)?;
            if archive::encode(&custody.snapshot())? != archive::encode(&plan.draft)? {
                return Err(Error::WitnessLost("preparation changed custody draft"));
            }
            prepared
        };
        // `selected` is this call's last own archive publication; the exclusive owner
        // publishes nothing else before proving.
        let derivation = CallDerivationV1 {
            binding: DerivationBindingV1::new(entry.binding, source_digest, selected, &plan)?,
            native: prepared,
        };
        // A selected plan no longer needs its staging batch. Cleanup is idempotent;
        // failure cannot authorize replanning, another signature or a monetary rollback.
        self.archive
            .remove(ArchiveKey::PreparationDraft(request.request_id()))?;
        let frozen = if let Some(capsule) = entry.capsule {
            self.frozen(capsule)?
        } else {
            // Design §5.3: check this phone before proving; commit checks it again.
            self.require_runtime_capacity()?;
            // The checkpoint binds every custody root and the archive-indexed head the
            // derivation read. Any change is foreign-writer evidence, refused before a proof.
            let (checkpoint, _) = self.manifest()?;
            if DerivationBindingV1::new(entry.binding, source_digest, checkpoint, &plan)?
                != derivation.binding
            {
                return Err(Error::WitnessLost("retained derivation binding"));
            }
            let frozen = self.proofs.prove_preparation(
                &request,
                &source,
                derivation.native,
                &plan.native,
            )?;
            // Proving takes no custody. Before any publication, the retained draft must pass
            // the same successor checks as `PreparationCustodyV1::finish` on durable objects.
            plan.draft.require(
                &mut super::super::object_workspace::ReadOnlyWorkspace::new(&mut self.archive),
                &frozen.capsule.body().successor_state,
            )?;
            require_frozen(&request, &source_digest, &frozen)?;
            let original = archive::encode(&frozen)?;
            if original.len() > FROZEN_BOUND {
                return Err(Error::Invalid("prepared capsule size"));
            }
            let capsule = frozen.capsule.custody_digest();
            self.archive.put(ArchiveKey::Capsule(capsule), &original)?;
            entry.capsule = Some(capsule);
            entry.capsule_commitment = Some(frozen.capsule.receipt_commitment());
            entry.operation = Some(frozen.capsule.body().operation_id);
            let address = entry
                .plan
                .ok_or(Error::WitnessLost("prepared capsule plan"))?;
            if let Some(previous) = manifest.capsule_plans.get(&mut self.archive, &capsule)? {
                if previous != address {
                    return Err(Error::WitnessLost("conflicting capsule plan"));
                }
            }
            manifest.capsule_plans =
                manifest
                    .capsule_plans
                    .set(&mut self.archive, capsule, &address)?;
            self.publish_preparation(&mut selected, &mut manifest, request.request_id(), &entry)?;
            frozen
        };
        require_frozen(&request, &source_digest, &frozen)?;
        if entry.operation != Some(frozen.capsule.body().operation_id)
            || entry.capsule_commitment != Some(frozen.capsule.receipt_commitment())
        {
            return Err(Error::WitnessLost("prepared operation identity"));
        }
        // Recheck source selection after any preparation/publication work. This is under the
        // same exclusive owner; commit independently repeats full native and Advance checks.
        let (_, current) = self.sync_manifest()?;
        if current.capsule != source_digest {
            return Ok(Completion::NotPerformed(NotPerformed::StaleHead));
        }
        self.commit(frozen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_state_v1::{BlacklistOriginalReferenceV1, tests::fixture};

    #[test]
    fn permanent_preparation_pair_is_complete_nonzero_and_fits_existing_index() {
        let full = Entry {
            binding: [6; 32],
            kind: KagemushaWalletOperationKindV1::Retiring,
            request: Some([1; 32]),
            plan: Some([2; 32]),
            capsule: Some([3; 32]),
            capsule_commitment: Some([4; 32]),
            operation: Some([5; 32]),
        };
        full.require_binding().unwrap();
        assert!(archive::encode(&full).unwrap().len() <= index::INDEX_VALUE_LIMIT);
        for mutation in 0..8 {
            let mut changed: Entry = archive::decode(&archive::encode(&full).unwrap()).unwrap();
            match mutation {
                0 => changed.capsule = None,
                1 => changed.capsule_commitment = None,
                2 => changed.operation = None,
                3 => changed.capsule = Some([0; 32]),
                4 => changed.capsule_commitment = Some([0; 32]),
                5 => changed.operation = Some([0; 32]),
                6 => changed.binding = [0; 32],
                _ => changed.request = None,
            }
            assert!(changed.require_binding().is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn derivation_binding_changes_with_each_of_its_five_fields() {
        use super::DerivationBindingV1 as B;
        let exact = B::of([1; 32], [2; 32], [3; 32], b"choices", b"draft");
        assert!(exact == B::of([1; 32], [2; 32], [3; 32], b"choices", b"draft"));
        for changed in [
            B::of([9; 32], [2; 32], [3; 32], b"choices", b"draft"),
            B::of([1; 32], [9; 32], [3; 32], b"choices", b"draft"),
            B::of([1; 32], [2; 32], [9; 32], b"choices", b"draft"),
            B::of([1; 32], [2; 32], [3; 32], b"choiceS", b"draft"),
            B::of([1; 32], [2; 32], [3; 32], b"choices", b"drafT"),
        ] {
            assert!(exact != changed);
        }
    }

    #[test]
    fn prepared_blacklist_binds_the_complete_original_through_its_retained_reference() {
        let blacklist: KagemushaWalletBlacklistV1 = fixture("KagemushaWalletBlacklistV1");
        let complete = blacklist.to_canonical_bytes().unwrap();
        let reference =
            BlacklistOriginalReferenceV1::for_original(&blacklist.body.scheme_id, &complete)
                .unwrap()
                .to_canonical_bytes()
                .unwrap();
        let mut body =
            fixture::<KagemushaWalletRecoveryCapsuleV1>("KagemushaWalletRecoveryCapsuleV1")
                .body()
                .clone();
        // This test checks original binding only, not capsule or issuer admission.
        body.scheme_id = blacklist.body.scheme_id;
        body.retained_inputs = vec![KagemushaWalletRetainedInputV1 {
            role: KagemushaWalletRetainedInputRoleV1::PolicyUpdate,
            bytes: reference,
        }];
        let kind = KagemushaWalletPolicyUpdateKindV1::Blacklist;
        assert!(policy_original(&body, kind, &complete));
        let mut changed = complete.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(!policy_original(&body, kind, &changed));
        body.retained_inputs[0].bytes = complete.clone();
        assert!(!policy_original(&body, kind, &complete));
    }

    #[test]
    fn prepared_policy_original_requires_one_exact_retained_input() {
        let complete = vec![1, 2, 3];
        let mut body =
            fixture::<KagemushaWalletRecoveryCapsuleV1>("KagemushaWalletRecoveryCapsuleV1")
                .body()
                .clone();
        body.retained_inputs = vec![KagemushaWalletRetainedInputV1 {
            role: KagemushaWalletRetainedInputRoleV1::PolicyUpdate,
            bytes: complete.clone(),
        }];
        for kind in [
            KagemushaWalletPolicyUpdateKindV1::Credential,
            KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            KagemushaWalletPolicyUpdateKindV1::TimeAnchor,
            KagemushaWalletPolicyUpdateKindV1::QuotaShare,
        ] {
            assert!(policy_original(&body, kind, &complete));
            assert!(!policy_original(&body, kind, &[1, 2, 4]));
            body.retained_inputs.push(body.retained_inputs[0].clone());
            assert!(!policy_original(&body, kind, &complete));
            body.retained_inputs.pop();
        }
        body.retained_inputs.clear();
        assert!(!policy_original(
            &body,
            KagemushaWalletPolicyUpdateKindV1::Credential,
            &complete,
        ));
    }
}
