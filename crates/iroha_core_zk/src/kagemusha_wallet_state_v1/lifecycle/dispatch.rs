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

// Every signed policy update is retained inline as its exact complete original.
fn policy_original(body: &KagemushaWalletRecoveryBodyV1, complete: &[u8]) -> bool {
    let mut inputs = body
        .retained_inputs
        .iter()
        .filter(|input| input.role == KagemushaWalletRetainedInputRoleV1::PolicyUpdate);
    inputs.next().is_some_and(|input| input.bytes == complete) && inputs.next().is_none()
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
            OperationActionV1::Send { request } => {
                let KagemushaWalletEffectV1::Send { send_ordinal, .. } =
                    &capsule.body().statement.effect
                else {
                    return Err(Error::Invalid("prepared Send effect"));
                };
                // Intent retains the receiver's open Request; Native preparation
                // retains its exact payer completion. Rebuild only those payer
                // fields from this frozen Send, then compare the complete original
                // including every receiver term, certificate and signature.
                let received: KagemushaWalletRequestV1 = archive::decode(request)?;
                let completed = valid(received.complete(&frozen.credential, *send_ordinal))?;
                original(frozen, R::Request, &archive::encode(&completed)?)
            }
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
                policy_original(frozen.capsule.body(), update)
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

    /// Retire only an authenticated stale ArchiveSent plan that Advance never selected.
    /// The durable Entry keeps its exact request and stale capsule locator until every unlink
    /// succeeds. A crash therefore repeats these idempotent removals before replacing the plan.
    /// No selected completion, uncertain lookup or monetary operation can reach this path.
    fn retire_archive_plan(
        &mut self,
        request: &NativeIntentV1,
        source: &[u8; 32],
        plan: &Plan,
        entry: &mut Entry,
        manifest: &mut manifest::Manifest,
    ) -> Result<(), Error> {
        entry.require_binding()?;
        if request.kind() != KagemushaWalletOperationKindV1::ArchiveSent
            || entry.kind != KagemushaWalletOperationKindV1::ArchiveSent
            || entry.plan.is_none()
            || entry.request != Some(plan.request_object)
            || plan.source == *source
        {
            return Err(Error::WitnessLost("stale Archive retirement binding"));
        }
        if let Some(operation) = entry.operation {
            let capsule = entry
                .capsule
                .ok_or(Error::WitnessLost("stale Archive capsule"))?;
            // Low-level Unknown alone is insufficient: an older committed output may be
            // missing. The permanent authenticated operation index must also prove absence.
            if !matches!(self.custody.lookup(&operation)?, Lookup::Unknown)
                || self
                    .missing_retained_output(&operation, Some(&capsule))?
                    .is_some()
            {
                return Err(Error::WitnessLost("stale Archive already selected"));
            }
            let plan_address = entry.plan.ok_or(Error::WitnessLost("stale Archive plan"))?;
            if manifest
                .capsule_plans
                .get(&mut self.archive, &capsule)?
                .as_deref()
                != Some(plan_address.as_slice())
            {
                return Err(Error::WitnessLost("stale Archive capsule plan binding"));
            }
        }
        // The source-selected stale Entry plus authenticated nonselection authorizes retiring
        // these preparation artifacts. Keep its locator durable until both removals succeed.
        // No object/index writes precede the removals: grouped stores refuse pending writes.
        self.archive
            .remove(ArchiveKey::PreparationDraft(request.request_id()))?;
        if let Some(capsule) = entry.capsule {
            self.archive.remove(ArchiveKey::Capsule(capsule))?;
            manifest.capsule_plans = manifest.capsule_plans.remove(&mut self.archive, &capsule)?;
        }
        entry.capsule = None;
        entry.capsule_commitment = None;
        entry.operation = None;
        entry.plan = None;
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
                self.require_retained_output(operation, &retained)?;
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
            Lookup::Unknown => self.missing_retained_output(operation, Some(capsule))?,
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
    /// or uncertain Advance. A stale prepared source returns `NotPerformed` without rebasing.
    pub fn execute(&mut self, request: OperationRequestV1) -> Result<Completion, Error> {
        self.execute_intent(NativeIntentV1::user(request))
    }

    /// [`Self::execute`] for a reviewed request whose step a speculation proved before the
    /// user confirmed. Planning and proving use it only for an identical derivation; every
    /// other check, the durable plan, commit and the sole Advance are unchanged.
    pub(crate) fn execute_speculated(
        &mut self,
        request: OperationRequestV1,
        speculative: Option<N::Speculative>,
    ) -> Result<Completion, Error> {
        self.execute_intent_with(NativeIntentV1::user(request), speculative)
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
        self.execute_intent_with(request, None)
    }

    fn execute_intent_with(
        &mut self,
        request: NativeIntentV1,
        speculative: Option<N::Speculative>,
    ) -> Result<Completion, Error> {
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
        let restoration = iroha_plonk::work_metrics::WorkTimer::start(
            iroha_plonk::work_metrics::WorkPhase::SourceRestore,
        );
        let released = self.indexed_step(&manifest, sequence)?;
        let source_digest = released.frozen.capsule.custody_digest();
        let mut held_plan = entry
            .plan
            .map(|plan| archive::decode::<Plan>(&self.archive.read_object(&plan, PLAN_BOUND)?))
            .transpose()?;
        if let Some(plan) = &held_plan {
            plan.require(&self.scheme_id, &self.wallet_id, &request, &bytes)?;
        }
        drop(restoration);
        if held_plan
            .as_ref()
            .is_some_and(|plan| plan.source != source_digest)
        {
            if request.kind() != KagemushaWalletOperationKindV1::ArchiveSent {
                return Ok(Completion::NotPerformed(NotPerformed::StaleHead));
            }
            // A deferred, never-selected Archive may replan on the new head. The helper
            // preserves a durable recovery locator until stale artifact retirement finishes.
            self.retire_archive_plan(
                &request,
                &source_digest,
                held_plan
                    .as_ref()
                    .ok_or(Error::WitnessLost("stale Archive plan"))?,
                &mut entry,
                &mut manifest,
            )?;
            held_plan = None;
        }
        let restoration = iroha_plonk::work_metrics::WorkTimer::start(
            iroha_plonk::work_metrics::WorkPhase::SourceRestore,
        );
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
        drop(restoration);
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
                speculative.as_ref(),
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
                manifest.blacklist.clone(),
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
            self.require_runtime_capacity(NativeAdmissionPhaseV1::BeforeProve)?;
            // The checkpoint binds every custody root and the archive-indexed head the
            // derivation read. Any change is foreign-writer evidence, refused before a proof.
            let (checkpoint, _) = self.manifest()?;
            if DerivationBindingV1::new(entry.binding, source_digest, checkpoint, &plan)?
                != derivation.binding
            {
                return Err(Error::WitnessLost("retained derivation binding"));
            }
            let frozen = match speculative {
                // A step proved during review is frozen only for this identical derivation.
                Some(speculative) => self.proofs.prove_speculated(
                    &request,
                    &source,
                    derivation.native,
                    &plan.native,
                    speculative,
                )?,
                None => self.proofs.prove_preparation(
                    &request,
                    &source,
                    derivation.native,
                    &plan.native,
                )?,
            };
            // Proving takes no custody. Before any publication, the retained draft must pass
            // the same successor checks as `PreparationCustodyV1::finish` on durable objects.
            plan.draft.require(
                &mut super::super::object_workspace::ReadOnlyWorkspace::new(&mut self.archive),
                &frozen.capsule.body().successor_state,
            )?;
            require_frozen(&request, &source_digest, &frozen)?;
            // Observe only this pre-Advance publication; no outcome is changed.
            let publication = iroha_plonk::work_metrics::WorkTimer::start(
                iroha_plonk::work_metrics::WorkPhase::SigmaPublish,
            );
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
            drop(publication);
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
    use crate::kagemusha_wallet_state_v1::tests::fixture;

    fn prepared_send() -> (KagemushaWalletRequestV1, FrozenTransition) {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        let row = vectors["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"].as_str() == Some("Request"))
            .unwrap();
        let envelope: KagemushaWalletEnvelopeV1 =
            archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
        let KagemushaWalletMessageV1::Request { request } = envelope.message else {
            panic!("Request fixture");
        };
        request
            .verify_open(&fixture("KagemushaWalletSchemeV1"))
            .unwrap();
        let credential: KagemushaWalletCredentialV1 = fixture("KagemushaWalletCredentialV1");
        let completed = request.complete(&credential, 3).unwrap();
        completed
            .verify(&fixture("KagemushaWalletSchemeV1"))
            .unwrap();
        let previous = crate::kagemusha_wallet_state_v1::tests::bootstrap();
        let mut frozen = crate::kagemusha_wallet_state_v1::tests::frozen(
            Some(&previous),
            KagemushaWalletEffectV1::Send {
                credit_id: completed.credit_id(),
                receiver_wallet_id: completed.body.receiver_wallet_id,
                send_ordinal: completed.body.send_ordinal,
                amount: completed.body.amount,
                fee: completed.body.fee,
                request: completed.request_digest(),
                accepted_lower_ms: completed.body.receiver_accepted_time_ms,
                accepted_upper_ms: completed.body.receiver_accepted_time_ms,
            },
        );
        let mut body = frozen.capsule.body().clone();
        body.retained_inputs = vec![KagemushaWalletRetainedInputV1 {
            role: KagemushaWalletRetainedInputRoleV1::Request,
            bytes: archive::encode(&completed).unwrap(),
        }];
        frozen.capsule = body.freeze().unwrap().seal([0; 32]).unwrap();
        frozen.validate().unwrap();
        (request, frozen)
    }

    fn send_intent(request: &KagemushaWalletRequestV1) -> NativeIntentV1 {
        NativeIntentV1::user(OperationRequestV1 {
            request_id: [71; 32],
            action: OperationActionV1::Send {
                request: archive::encode(request).unwrap(),
            },
        })
    }

    #[test]
    fn prepared_send_accepts_exact_completion_of_retained_open_request() {
        // Signed Request/credential vectors with explicit stand-in proof data.
        // This exercises the dispatcher binding, not proof or hardware admission.
        let (open, frozen) = prepared_send();
        let source = frozen.capsule.body().predecessor_capsule_digest;
        assert!(!original(
            &frozen,
            KagemushaWalletRetainedInputRoleV1::Request,
            &archive::encode(&open).unwrap()
        ));
        require_frozen(&send_intent(&open), &source, &frozen).unwrap();
        let completed = open.complete(&frozen.credential, 3).unwrap();
        require_frozen(&send_intent(&completed), &source, &frozen).unwrap();
    }

    #[test]
    fn prepared_send_rejects_changed_terms_signature_payer_and_ordinal() {
        let (open, frozen) = prepared_send();
        let source = frozen.capsule.body().predecessor_capsule_digest;
        for mutation in 0..8 {
            let mut changed = open.clone();
            match mutation {
                0 => changed.body.receiver_wallet_id[0] ^= 1,
                1 => changed.body.receiver_account_digest[0] ^= 1,
                2 => changed.body.amount += 1,
                3 => changed.body.fee += 1,
                4 => changed.body.nonce[0] ^= 1,
                5 => {
                    changed = open.complete(&frozen.credential, 4).unwrap();
                }
                6 => {
                    changed = open.complete(&frozen.credential, 3).unwrap();
                    changed.body.payer_wallet_id[0] ^= 1;
                }
                _ => {
                    let mut signature = changed.signature.as_ref().to_vec();
                    signature[0] ^= 1;
                    changed.signature =
                        KagemushaDeviceSignatureV1::from_raw_bytes(&signature).unwrap();
                }
            }
            assert!(
                require_frozen(&send_intent(&changed), &source, &frozen).is_err(),
                "mutation {mutation}"
            );
        }
        let completed = open.complete(&frozen.credential, 3).unwrap();
        let mut duplicate = frozen.clone();
        let mut body = duplicate.capsule.body().clone();
        body.retained_inputs.push(body.retained_inputs[0].clone());
        duplicate.capsule = body.freeze().unwrap().seal([0; 32]).unwrap();
        assert!(require_frozen(&send_intent(&completed), &source, &duplicate).is_err());
        assert!(require_frozen(&send_intent(&open), &[0x99; 32], &frozen).is_err());
    }

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
        assert!(policy_original(&body, &complete));
        assert!(!policy_original(&body, &[1, 2, 4]));
        body.retained_inputs.push(body.retained_inputs[0].clone());
        assert!(!policy_original(&body, &complete));
        body.retained_inputs.clear();
        assert!(!policy_original(&body, &complete));
    }
}
