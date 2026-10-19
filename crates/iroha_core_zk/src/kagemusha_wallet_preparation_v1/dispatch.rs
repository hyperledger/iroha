//! Concrete operation derivation from the coordinator's sealed source custody.
//!
//! Every call starts from a fresh unpublished map draft and retains the same native
//! choices. Storage errors remain storage errors. Foreign requests never supply a
//! map path, policy object, successor state, statement, or proof selector.

use crate::kagemusha_wallet_artifacts_v1::producer_inventory::{
    ImportedSigmaV1, OriginalSourceV1, QualifiedWalletSourcesV1,
};
use crate::kagemusha_wallet_state_v1::{
    self as state, NativeIntentV1, OperationActionV1 as Action, PreparationCustodyV1,
    PreparationMapV1 as Map, PreparationOriginalV1 as Original, PreparationSourceV1,
};
use iroha_plonk::{ProverRandomness, keys::pk::artifact::ReadConfig};

use super::*;

type Result<T> = core::result::Result<T, state::Error>;

pub(super) fn proof<T>(result: core::result::Result<T, Error>) -> Result<T> {
    result.map_err(|error| match error {
        Error::DecodeResource(original) => state::Error::DecodeResource(original),
        Error::Unavailable => state::Error::ArtifactsUnavailable("native operation artifact"),
        Error::Cancelled => state::Error::Cancelled,
        Error::Blocked(field) => state::Error::Blocked(field),
        Error::Entropy => {
            crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderErrorV1::Unavailable(
                crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Platform(0),
            )
            .into()
        }
        _ => state::Error::Proof("installed native operation preparation"),
    })
}

fn model<T>(result: core::result::Result<T, KagemushaWalletValidationErrorV1>) -> Result<T> {
    result.map_err(|error| match error {
        KagemushaWalletValidationErrorV1::BlockedAccount { field } => state::Error::Blocked(field),
        _ => state::Error::Invalid("native operation original"),
    })
}
fn read_model_original<T>(
    read: impl FnOnce() -> core::result::Result<T, KagemushaWalletValidationErrorV1>,
) -> Result<T> {
    state::read_model_original(read, state::Error::Invalid("native operation original"))
}
fn load_receipt_original(bytes: &[u8]) -> Result<KagemushaWalletLoadReceiptV1> {
    state::read_model_original(
        || KagemushaWalletLoadReceiptV1::decode_canonical(bytes),
        state::Error::Invalid("native Load receipt original"),
    )
}

fn decode<T>(bytes: &[u8], maximum: usize) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(state::Error::Invalid("native original frame bound"));
    }
    norito::core::classify_decode_attempt(|| {
        norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
    })
    .map_err(|error| {
        state::decode_attempt_error(
            error,
            state::Error::Invalid("native original canonical frame"),
        )
    })
}

fn required_original(custody: &mut PreparationCustodyV1<'_>, role: Original) -> Result<Vec<u8>> {
    custody
        .original(role)?
        .ok_or(state::Error::WitnessLost("required native original"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Derivation {
    BeforeAdvance,
    ReleasedFold,
}

pub(super) enum Step {
    Archive(Box<ArchiveStepV1>),
    Load(Box<LoadStepV1>),
    Monetary(Box<MonetaryStepV1>),
    Refresh(Box<RefreshStepV1>),
    Consuming(Box<ConsumingStepV1>),
}

/// Opaque derivation from the selected source, ready for one actual sigma import.
pub struct PreparedOperationV1 {
    owner: AuthenticatedCredentialV1,
    predecessor: Option<FoldedStateV1>,
    step: Step,
    send_usage: Option<KagemushaWalletQuotaUsageArrayV1>,
}

/// Borrowed inputs from the qualified owner and the already decoded durable plan.
pub struct OperationPreparationV1<'a> {
    /// Existing complete source owner; its installation is checked during derivation.
    pub(crate) sources: &'a QualifiedWalletSourcesV1,
    /// Exact retained nonce and clock choices authenticated against this request and source.
    pub(crate) choices: &'a NativeChoicesV1,
    /// The same bounded working-memory budget used by the native owner or fold worker.
    pub(crate) budget: MemoryBudget,
}

/// One native derivation, consumed at most once by proving inside the coordinator call
/// that made it. It binds the exact native plan bytes, source capsule and installed verifier
/// manifest it was derived from. It has no clone, codec or `Send`, so no review, slot,
/// worker, process or later call can retain it, and it grants no Advance authority: commit
/// always derives again from the durable plan. A review's speculative `σ_send` proves from its
/// own separate derivation (`SpeculativeSendStepV1`) and never yields one of these.
///
/// ```
/// use iroha_core_zk::kagemusha_wallet_preparation_v1::NativePreparedOperationV1;
/// fn needs_send<T: Send>(_: T) {}
/// fn consume(token: NativePreparedOperationV1) { drop(token); }
/// ```
/// ```compile_fail,E0599
/// use iroha_core_zk::kagemusha_wallet_preparation_v1::NativePreparedOperationV1;
/// fn needs_send<T: Send>(_: T) {}
/// fn consume(token: NativePreparedOperationV1) { drop(token.clone()); }
/// ```
/// ```compile_fail,E0277
/// use iroha_core_zk::kagemusha_wallet_preparation_v1::NativePreparedOperationV1;
/// fn needs_send<T: Send>(_: T) {}
/// fn consume(token: NativePreparedOperationV1) { needs_send(token); }
/// ```
/// ```compile_fail,E0382
/// use iroha_core_zk::kagemusha_wallet_preparation_v1::NativePreparedOperationV1;
/// fn needs_send<T: Send>(_: T) {}
/// fn consume(token: NativePreparedOperationV1) { drop(token); drop(token); }
/// ```
pub struct NativePreparedOperationV1 {
    prepared: PreparedOperationV1,
    binding: PreparedBindingV1,
    _call: core::marker::PhantomData<*const ()>,
}

#[derive(PartialEq, Eq)]
struct PreparedBindingV1 {
    plan: [u8; 32],
    source: [u8; 32],
    manifest: [u8; 32],
}

impl PreparedBindingV1 {
    fn new(plan: &[u8], source: [u8; 32], manifest: [u8; 32]) -> Self {
        Self {
            plan: crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1(
                plan,
            ),
            source,
            manifest,
        }
    }
}

impl NativePreparedOperationV1 {
    pub(crate) fn new(
        prepared: PreparedOperationV1,
        plan: &[u8],
        source: [u8; 32],
        manifest: [u8; 32],
    ) -> Self {
        Self {
            prepared,
            binding: PreparedBindingV1::new(plan, source, manifest),
            _call: core::marker::PhantomData,
        }
    }

    /// Release the derivation only for the exact plan, source and installation it bound.
    pub(crate) fn redeem(
        self,
        plan: &[u8],
        source: [u8; 32],
        manifest: [u8; 32],
    ) -> Result<PreparedOperationV1> {
        if self.binding != PreparedBindingV1::new(plan, source, manifest) {
            return Err(state::Error::WitnessLost("prepared operation binding"));
        }
        Ok(self.prepared)
    }
}

/// Move-only check of already verified inputs, consumed at the final Advance boundary.
/// Private construction prevents foreign callers from authorizing a timed Send.
pub struct NativeAdvanceCheckV1 {
    send: Option<Box<SendAdvanceCheck>>,
}
struct SendAdvanceCheck {
    owner: KagemushaWalletCredentialV1,
    request: KagemushaWalletRequestV1,
    state: KagemushaWalletStateV1,
    omega: KagemushaWalletLineagePublicV1,
    anchor: Option<KagemushaWalletAnchoredTimeV1>,
    share: Option<KagemushaWalletQuotaShareV1>,
    usage: KagemushaWalletQuotaUsageArrayV1,
    charges: Vec<KagemushaWalletQuotaChargeV1>,
    successor_usage: KagemushaWalletQuotaUsageArrayV1,
}
impl NativeAdvanceCheckV1 {
    pub(crate) const fn without_time() -> Self {
        Self { send: None }
    }
    pub(crate) fn check<F, P>(self, observations: &state::NativeObservationsV1<F, P>) -> Result<()>
    where
        F: crate::kagemusha_wallet_advance_v1::KagemushaWalletFsV1,
        P: crate::kagemusha_wallet_advance_v1::KagemushaWalletPlatformV1,
    {
        let Some(send) = self.send else {
            return Ok(());
        };
        let now = observations.time()?;
        let fresh = model(send.request.check_send(&KagemushaWalletSendInputsV1 {
            payer_credential: &send.owner,
            payer_state: &send.state,
            omega: &send.omega,
            anchored: send.anchor.as_ref(),
            now: Some(&now),
            // This commit's derivation applied the local blacklist under the same exclusive
            // owner; this recheck covers the time-dependent controls only.
            blacklist: None,
            quota_share: send.share.as_ref(),
            quota_usage: &send.usage,
        }))?;
        if fresh.quota_charges != send.charges || fresh.quota_usage != send.successor_usage {
            return Err(state::Error::Invalid(
                "Send crossed a quota charge boundary",
            ));
        }
        Ok(())
    }
}

impl PreparedOperationV1 {
    pub(crate) fn monetary(&self) -> Option<&MonetaryStepV1> {
        match &self.step {
            Step::Monetary(step) => Some(step),
            _ => None,
        }
    }
    pub(crate) fn owner(&self) -> &AuthenticatedCredentialV1 {
        &self.owner
    }
    fn selector(&self) -> Result<u8> {
        use KagemushaWalletOperationKindV1 as K;
        Ok(match &self.step {
            Step::Load(_) => 1,
            Step::Archive(_) => 7,
            Step::Monetary(s) => match s.statement().effect.kind() {
                K::Send => {
                    2 + u8::try_from(s.relation().enabled_controls())
                        .map_err(|_| state::Error::Invalid("Send control selector"))?
                }
                K::Receive => 6,
                _ => return Err(state::Error::Invalid("monetary selector")),
            },
            Step::Refresh(_) => 9,
            Step::Consuming(s) => match s.statement().effect.kind() {
                K::Unload => 8,
                K::Retiring => 10,
                _ => return Err(state::Error::Invalid("consuming selector")),
            },
        })
    }

    /// Retain only the verified inputs needed by the final fresh-time check.
    /// Construction occurs while the coordinator still owns its sealed source view.
    pub(crate) fn advance_check(
        &self,
        preparation: &PreparationV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
    ) -> Result<NativeAdvanceCheckV1> {
        let Step::Monetary(step) = &self.step else {
            return Ok(NativeAdvanceCheckV1::without_time());
        };
        if step.statement().effect.kind() != KagemushaWalletOperationKindV1::Send {
            return Ok(NativeAdvanceCheckV1::without_time());
        }
        let predecessor = self
            .predecessor
            .as_ref()
            .ok_or(state::Error::FoldRequired)?;
        let before = predecessor.source_state();
        // Every time-independent control was already checked against the fixed source.
        // Controls off cannot acquire a clock dependency during commit.
        if !before.send_requires_time_anchor() {
            return Ok(NativeAdvanceCheckV1::without_time());
        }
        let scheme = preparation.installed.verifier().scheme();
        let share = if before.is_active(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1) {
            let original = required_original(custody, Original::QuotaShare)?;
            Some(read_model_original(|| {
                KagemushaWalletQuotaShareV1::decode_canonical(&original, &scheme.scheme_id())
            })?)
        } else {
            None
        };
        let usage = self
            .send_usage
            .as_ref()
            .ok_or(state::Error::Proof("missing original Send quota array"))?;
        if usage.root() != before.core.quota_usage_root {
            return Err(state::Error::Proof("original Send quota root"));
        }
        let original = step
            .send_check()
            .ok_or(state::Error::Proof("missing original Send check"))?;
        Ok(NativeAdvanceCheckV1 {
            send: Some(Box::new(SendAdvanceCheck {
                owner: self.owner.credential,
                request: step.request().clone(),
                state: *before,
                omega: predecessor.lineage().public,
                anchor: custody.anchored_time()?,
                share,
                usage: *usage,
                charges: original.quota_charges.clone(),
                successor_usage: original.quota_usage,
            })),
        })
    }

    /// Rebuild the selected σ key from its qualified admission seal after revalidating
    /// its exact signed originals, prove the exact derived witness, and fully verify
    /// the frozen capsule. This performs no signing or publication.
    pub(crate) fn prove(
        &self,
        preparation: &PreparationV1<'_>,
        sources: &QualifiedWalletSourcesV1,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        budget: MemoryBudget,
    ) -> Result<state::FrozenTransition> {
        if sources.installation()
            != (
                self.owner.credential.body.scheme_id,
                self.owner.manifest_digest,
            )
        {
            return Err(state::Error::Proof("foreign sigma source installation"));
        }
        let imported = sources
            .import_sigma(self.selector()?, originals, config)
            .map_err(|error| {
                if error.is_unavailable() {
                    state::Error::ArtifactsUnavailable("qualified sigma original import")
                } else {
                    state::Error::Proof("qualified sigma original import")
                }
            })?;
        let randomness = ProverRandomness::hedged();
        let sigma = match (&self.step, imported) {
            (Step::Archive(s), ImportedSigmaV1::Archive(p)) => {
                proof(preparation.prove_archive_sigma(
                    &self.owner,
                    s.witness(),
                    s.statement(),
                    &p,
                    randomness,
                    budget,
                ))?
            }
            (Step::Load(s), ImportedSigmaV1::Load(p)) => proof(preparation.prove_load_sigma(
                &self.owner,
                s.witness(),
                s.statement(),
                &p,
                randomness,
                budget,
            ))?,
            (Step::Monetary(s), ImportedSigmaV1::Monetary(p)) => {
                proof(preparation.prove_monetary_sigma(s, &p, randomness, budget))?
            }
            (Step::Refresh(s), ImportedSigmaV1::Refresh(p)) => {
                proof(preparation.prove_refresh_sigma(&self.owner, s, &p, randomness, budget))?
            }
            (Step::Consuming(s), ImportedSigmaV1::Unload(p)) => {
                proof(preparation.prove_unload_sigma(
                    &self.owner,
                    s.witness(),
                    s.statement(),
                    &p,
                    randomness,
                    budget,
                ))?
            }
            (Step::Consuming(s), ImportedSigmaV1::Retiring(p)) => {
                proof(preparation.prove_retiring_sigma(
                    &self.owner,
                    s.witness(),
                    s.statement(),
                    &p,
                    randomness,
                    budget,
                ))?
            }
            _ => return Err(state::Error::Proof("qualified sigma operation mismatch")),
        };
        self.freeze(preparation, sigma, budget)
    }

    /// This derivation's Send step, for one speculative σ; `None` for every other operation.
    pub(crate) fn into_speculative_send(self) -> Result<Option<SpeculativeSendStepV1>> {
        let selector = self.selector()?;
        Ok(match self.step {
            Step::Monetary(step)
                if step.statement().effect.kind() == KagemushaWalletOperationKindV1::Send =>
            {
                Some(SpeculativeSendStepV1 { selector, step })
            }
            _ => None,
        })
    }

    /// Freeze `speculative` without proving when it was proved for exactly this derivation's
    /// Send statement and relation; `Ok(None)` leaves it unused. The frozen body verifies the
    /// σ in full like a fresh proof's, and commit derives and verifies again.
    pub(crate) fn freeze_speculated(
        &self,
        preparation: &PreparationV1<'_>,
        speculative: SpeculativeSigmaV1,
        budget: MemoryBudget,
    ) -> Result<Option<state::FrozenTransition>> {
        let Step::Monetary(step) = &self.step else {
            return Ok(None);
        };
        if step.statement().effect.kind() != KagemushaWalletOperationKindV1::Send
            || *step.statement() != speculative.statement
            || step.relation() != speculative.relation
        {
            return Ok(None);
        }
        self.freeze(preparation, speculative.sigma, budget)
            .map(Some)
    }

    pub(crate) fn verify_frozen(
        &self,
        preparation: &PreparationV1<'_>,
        frozen: &state::FrozenTransition,
        budget: MemoryBudget,
    ) -> Result<()> {
        let expected = self.body(
            preparation,
            frozen.capsule.body().step_proof.clone(),
            budget,
        )?;
        proof(expected.require_matches(frozen))?;
        Ok(())
    }

    fn freeze(
        &self,
        preparation: &PreparationV1<'_>,
        sigma: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<state::FrozenTransition> {
        proof(self.body(preparation, sigma, budget)?.seal_fresh())
    }

    fn body(
        &self,
        preparation: &PreparationV1<'_>,
        sigma: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<super::freeze::PreparedRecoveryV1> {
        match &self.step {
            Step::Load(s) => proof(preparation.body_load(&self.owner, s, sigma, budget)),
            Step::Archive(s) => proof(preparation.body_archive(&self.owner, s, sigma, budget)),
            Step::Monetary(s) => proof(preparation.body_monetary(
                &self.owner,
                s,
                self.predecessor.as_ref(),
                sigma,
                budget,
            )),
            Step::Refresh(s) => proof(preparation.body_refresh(&self.owner, s, sigma, budget)),
            Step::Consuming(s) => proof(
                preparation.body_consuming(
                    &self.owner,
                    s,
                    self.predecessor
                        .as_ref()
                        .ok_or(state::Error::FoldRequired)?,
                    sigma,
                    budget,
                ),
            ),
        }
    }
}

/// The Send step of one derivation, retained only to prove a speculative `σ_send` without the
/// wallet owner (design §5.1, Payment row). It holds no plan, custody, signing or Advance
/// capability: execute derives again from its durable plan and uses the σ only through
/// [`PreparedOperationV1::freeze_speculated`] for an identical statement and relation.
pub(crate) struct SpeculativeSendStepV1 {
    selector: u8,
    step: Box<MonetaryStepV1>,
}

/// A `σ_send` proved speculatively for one exact statement and relation. DATA only: it is
/// never signed or retained durably.
pub(crate) struct SpeculativeSigmaV1 {
    statement: KagemushaWalletStatementV1,
    relation: iroha_kagemusha_proof::witness::SigmaRelation,
    sigma: KagemushaWalletStepProofV1,
}

#[cfg(test)]
impl SpeculativeSigmaV1 {
    /// Test support: a σ DATA value with no proof authority, for review slot tests.
    pub(crate) fn for_test(statement: KagemushaWalletStatementV1, bytes: Vec<u8>) -> Self {
        Self {
            statement,
            relation: iroha_kagemusha_proof::witness::SigmaRelation::SEND,
            sigma: KagemushaWalletStepProofV1 { bytes },
        }
    }

    pub(crate) fn proof_bytes(&self) -> &[u8] {
        &self.sigma.bytes
    }
}

impl SpeculativeSendStepV1 {
    /// The installed σ selector of this Send's controls.
    pub(crate) const fn selector(&self) -> u8 {
        self.selector
    }

    /// Prove `σ_send` with `imported` under today's hedged prover randomness, exactly like
    /// execute's proof of this step, stopping at `preparation`'s cancellation signal. The
    /// prover is dropped before this returns; nothing is signed.
    pub(crate) fn prove(
        &self,
        preparation: &PreparationV1<'_>,
        imported: ImportedSigmaV1,
        budget: MemoryBudget,
    ) -> Result<SpeculativeSigmaV1> {
        let ImportedSigmaV1::Monetary(prover) = imported else {
            return Err(state::Error::Proof("qualified sigma operation mismatch"));
        };
        let sigma = proof(preparation.prove_monetary_sigma(
            &self.step,
            &prover,
            ProverRandomness::hedged(),
            budget,
        ));
        drop(prover);
        Ok(SpeculativeSigmaV1 {
            statement: *self.step.statement(),
            relation: self.step.relation(),
            sigma: sigma?,
        })
    }
}

impl PreparationV1<'_> {
    pub(crate) fn authenticate_credential_set(
        &self,
        credential: &[u8],
        certificates: &[u8],
    ) -> Result<AuthenticatedCredentialV1> {
        let scheme = self.installed.verifier().scheme();
        let current = read_model_original(|| {
            KagemushaWalletCredentialV1::decode_canonical(credential, &scheme.scheme_id())
        })?;
        let set: KagemushaWalletCertificateSetV1 =
            decode(certificates, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
        model(set.verify(scheme))?;
        let certificate = model(set.certificate(
            &current.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        ))?;
        proof(self.authenticate_credential(credential, &model(certificate.to_canonical_bytes())?))
    }

    /// Derive a typed operation exclusively from a coordinator-created source view.
    /// The context borrows choices decoded from the already durable native plan on retries.
    pub(crate) fn prepare_operation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        context: &OperationPreparationV1<'_>,
    ) -> Result<PreparedOperationV1> {
        self.derive_operation(
            request,
            source,
            custody,
            context,
            Derivation::BeforeAdvance,
            None,
        )
    }

    // Only the selected fold worker calls this. Own source, receipt, sigma and exact plan/draft
    // remain mandatory; incoming acceptance belongs to the total recursive predicates.
    pub(crate) fn restore_operation(
        &self,
        request: &NativeIntentV1,
        frozen: &state::FrozenTransition,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        context: &OperationPreparationV1<'_>,
    ) -> Result<PreparedOperationV1> {
        self.derive_operation(
            request,
            source,
            custody,
            context,
            Derivation::ReleasedFold,
            Some(frozen),
        )
    }

    fn derive_operation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        context: &OperationPreparationV1<'_>,
        derivation: Derivation,
        frozen: Option<&state::FrozenTransition>,
    ) -> Result<PreparedOperationV1> {
        let sources = context.sources;
        let nonce = context.choices.nonce();
        let observation = context.choices.time();
        let now = observation.as_ref();
        let budget = context.budget;
        let scheme = self.installed.verifier().scheme();
        if derivation == Derivation::BeforeAdvance {
            super::derivation_counts::record_before_advance();
            request.validate(scheme)?;
        }
        if sources.installation()
            != (
                scheme.scheme_id(),
                self.installed.verifier().manifest_digest(),
            )
        {
            return Err(state::Error::Proof("foreign complete source owner"));
        }
        let credential = required_original(custody, Original::CurrentCredential)?;
        let certificates = required_original(custody, Original::EnrollmentCertificates)?;
        let owner = self.authenticate_credential_set(&credential, &certificates)?;
        let released = source.released();
        let before = &released.frozen.capsule.body().successor_state;
        let predecessor = if request.kind().consumes_lineage() {
            Some(proof(self.folded_state(
                &owner,
                released,
                source.folded().ok_or(state::Error::FoldRequired)?,
                budget,
            ))?)
        } else {
            None
        };
        let mut send_usage = None;
        let step = if let Some(intent) = request.archive_request() {
            let payment = read_model_original(|| {
                KagemushaWalletPaymentV1::decode_canonical(&intent.payment, &scheme.scheme_id())
            })?;
            let pending = model(payment.pending_outgoing_leaf())?;
            let removal = custody.maps().remove(Map::Pending, &pending.credit_id)?;
            Step::Archive(Box::new(proof(match derivation {
                Derivation::BeforeAdvance => {
                    self.prepare_archive(&owner, released, intent, &removal, nonce, budget)
                }
                Derivation::ReleasedFold => {
                    self.restore_archive(&owner, released, intent, &removal, nonce, budget)
                }
            })?))
        } else {
            match &request
                .user_request()
                .ok_or(state::Error::Invalid("native intent kind"))?
                .action
            {
                Action::Load { receipt, finality } => {
                    let decoded = load_receipt_original(receipt)?;
                    let leaf = KagemushaWalletLoadLeafV1 {
                        ordinal: decoded.ordinal,
                        receipt_digest: model(decoded.receipt_digest())?,
                        amount: decoded.amount,
                    };
                    let insertion = custody.maps().insert(
                        Map::Recovery,
                        leaf.key(),
                        model(leaf.leaf_value())?,
                    )?;
                    Step::Load(Box::new(self.prepare_load(
                        &owner,
                        released,
                        custody,
                        LoadOriginalsV1 {
                            receipt,
                            finality,
                            insertion: &insertion,
                        },
                        context,
                    )?))
                }
                Action::Send { request: original } => {
                    let request: KagemushaWalletRequestV1 =
                        decode(original, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
                    model(request.verify(scheme))?;
                    let leaf = KagemushaWalletPendingOutgoingLeafV1 {
                        credit_id: request.credit_id(),
                        receiver_wallet_id: request.body.receiver_wallet_id,
                        send_ordinal: request.body.send_ordinal,
                        amount: request.body.amount,
                        fee: request.body.fee,
                        request_digest: request.request_digest(),
                    };
                    let pending = custody.maps().insert(
                        Map::Pending,
                        leaf.key(),
                        model(leaf.leaf_value())?,
                    )?;
                    let fee = if request.body.fee == 0 {
                        let (leaf, opening) = custody
                            .maps()
                            .member_or_low(Map::Fee, &request.credit_id())?;
                        SendFeeMapV1::Preserve { leaf, opening }
                    } else {
                        let leaf = KagemushaWalletFeeClaimLeafV1 {
                            credit_id: request.credit_id(),
                            fee: request.body.fee,
                            fee_schedule_digest: request.body.fee_schedule,
                        };
                        SendFeeMapV1::Insert(custody.maps().insert(
                            Map::Fee,
                            leaf.key(),
                            model(leaf.leaf_value())?,
                        )?)
                    };
                    // The payer's local block applies before the irreversible debit only; a fold
                    // replays a committed Send without it.
                    let blacklist = match derivation {
                        Derivation::BeforeAdvance => custody.local_blacklist()?,
                        Derivation::ReleasedFold => None,
                    };
                    let share = if before.is_active(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1) {
                        let original = required_original(custody, Original::QuotaShare)?;
                        Some(read_model_original(|| {
                            KagemushaWalletQuotaShareV1::decode_canonical(
                                &original,
                                &scheme.scheme_id(),
                            )
                        })?)
                    } else {
                        None
                    };
                    let anchored = if before.send_requires_time_anchor() {
                        custody.anchored_time()?
                    } else {
                        None
                    };
                    if anchored.is_some() != now.is_some() {
                        return Err(state::Error::Invalid("native Send clock choice"));
                    }
                    let usage = custody.maps().quota_usage()?;
                    send_usage = Some(usage);
                    let step = proof(self.prepare_send(
                        &owner,
                        predecessor.as_ref().ok_or(state::Error::FoldRequired)?,
                        original,
                        &SendControlsV1 {
                            anchored: anchored.as_ref(),
                            now,
                            blacklist: blacklist.as_ref(),
                            quota_share: share.as_ref(),
                            quota_usage: &usage,
                        },
                        &SendMapsV1 { pending, fee },
                        nonce,
                    ))?;
                    custody.maps().set_quota_usage(
                        &step
                            .send_check()
                            .ok_or(state::Error::Proof("native Send check"))?
                            .quota_usage,
                    )?;
                    Step::Monetary(Box::new(step))
                }
                Action::Receive {
                    payment,
                    payer_credential,
                    certificates,
                } => {
                    let decoded: KagemushaWalletPaymentV1 = match derivation {
                        Derivation::BeforeAdvance => read_model_original(|| {
                            KagemushaWalletPaymentV1::decode_canonical(payment, &scheme.scheme_id())
                        })?,
                        Derivation::ReleasedFold => {
                            decode(payment, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?
                        }
                    };
                    let frozen_request = frozen
                        .map(|frozen| {
                            let mut originals = frozen
                                .capsule
                                .body()
                                .retained_inputs
                                .iter()
                                .filter(|input| {
                                    input.role == KagemushaWalletRetainedInputRoleV1::Request
                                });
                            let original = originals
                                .next()
                                .ok_or(state::Error::WitnessLost("released Request original"))?;
                            if originals.next().is_some() {
                                return Err(state::Error::WitnessLost(
                                    "duplicate released Request",
                                ));
                            }
                            let request: KagemushaWalletRequestV1 =
                                decode(&original.bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
                            Ok((request.request_digest(), original.bytes.as_slice()))
                        })
                        .transpose()?;
                    let digest = match frozen_request {
                        Some((digest, _)) => digest,
                        None => model(decoded.signed_request())?.request_digest(),
                    };
                    let request_original = custody.issued_request(&digest)?;
                    if frozen_request.is_some_and(|(_, bytes)| bytes != request_original) {
                        return Err(state::Error::WitnessLost(
                            "issued/released Request mismatch",
                        ));
                    }
                    let request: KagemushaWalletRequestV1 =
                        decode(&request_original, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?;
                    if request.request_digest() != digest {
                        return Err(state::Error::WitnessLost("issued Request identity"));
                    }
                    let leaf = KagemushaWalletConsumedCreditLeafV1 {
                        credit_id: request.credit_id(),
                        amount: request.body.amount,
                        receive_sequence: before
                            .core
                            .sequence
                            .checked_add(1)
                            .ok_or(state::Error::Invalid("Receive sequence"))?,
                    };
                    let consumed = custody.maps().insert(
                        Map::Consumed,
                        leaf.key(),
                        model(leaf.leaf_value())?,
                    )?;
                    let step = match derivation {
                        // The receiver's local block applies before acceptance only; a fold
                        // replays a committed Receive without it.
                        Derivation::BeforeAdvance => self.prepare_receive(
                            &owner,
                            released,
                            &request_original,
                            payment,
                            payer_credential,
                            certificates,
                            custody.local_blacklist()?.as_ref(),
                            &ReceiveMapsV1 { consumed },
                            nonce,
                            budget,
                        ),
                        Derivation::ReleasedFold => self.restore_receive(
                            &owner,
                            released,
                            &request_original,
                            payment,
                            payer_credential,
                            certificates,
                            &ReceiveMapsV1 { consumed },
                            nonce,
                            budget,
                        ),
                    };
                    Step::Monetary(Box::new(proof(step)?))
                }
                Action::Refresh {
                    kind,
                    update,
                    certificates,
                } => {
                    let successor = if *kind == KagemushaWalletPolicyUpdateKindV1::Credential {
                        Some(self.authenticate_credential_set(update, certificates)?)
                    } else {
                        None
                    };
                    let quota = if *kind == KagemushaWalletPolicyUpdateKindV1::QuotaShare {
                        Some(model(
                            model(KagemushaWalletQuotaRefreshWitnessV1::from_usage(
                                &custody.maps().quota_usage()?,
                            ))?
                            .to_canonical_bytes(),
                        )?)
                    } else {
                        None
                    };
                    let owners = RefreshOwnersV1 {
                        current: &owner,
                        successor: successor.as_ref().unwrap_or(&owner),
                    };
                    let step = proof(self.prepare_refresh(
                        owners,
                        released,
                        RefreshOriginalsV1 {
                            kind: *kind,
                            update,
                            certificates,
                            quota: quota.as_deref(),
                        },
                        nonce,
                        budget,
                    ))?;
                    let role = match kind {
                        KagemushaWalletPolicyUpdateKindV1::Credential => {
                            Original::CurrentCredential
                        }
                        KagemushaWalletPolicyUpdateKindV1::SchemePolicy => Original::SchemePolicy,
                        KagemushaWalletPolicyUpdateKindV1::QuotaShare => Original::QuotaShare,
                        KagemushaWalletPolicyUpdateKindV1::TimeAnchor => Original::TimeAnchor,
                    };
                    custody.retain_successor_original(role, update)?;
                    if *kind == KagemushaWalletPolicyUpdateKindV1::Credential {
                        custody.retain_successor_original(
                            Original::EnrollmentCertificates,
                            certificates,
                        )?;
                    }
                    if *kind == KagemushaWalletPolicyUpdateKindV1::QuotaShare {
                        let share = read_model_original(|| {
                            KagemushaWalletQuotaShareV1::decode_canonical(
                                update,
                                &scheme.scheme_id(),
                            )
                        })?;
                        let usage = custody.maps().quota_usage()?;
                        let changed = model(before.refresh_policy(
                            KagemushaWalletPolicyUpdateV1::QuotaShare {
                                share: &share,
                                usage: &usage,
                            },
                        ))?;
                        custody.maps().set_quota_usage(
                            changed
                                .quota_usage
                                .as_ref()
                                .ok_or(state::Error::Invalid("native quota refresh"))?,
                        )?;
                    }
                    return Ok(PreparedOperationV1 {
                        owner: successor.unwrap_or(owner),
                        predecessor,
                        step: Step::Refresh(Box::new(step)),
                        send_usage: None,
                    });
                }
                Action::Unload { amount, charge } => {
                    let online_charge = match charge {
                        Some(original) => {
                            read_model_original(|| {
                                KagemushaWalletChargeQuoteV1::decode_canonical(
                                    &original.quote,
                                    &scheme.scheme_id(),
                                )
                            })?
                            .body
                            .online_charge
                        }
                        None => 0,
                    };
                    let leaf = KagemushaWalletRedeemLeafV1 {
                        ordinal: before.core.next_redeem,
                        nullifier: kagemusha_wallet_unload_nullifier_v1(
                            &before.core.scheme_id,
                            &before.core.wallet_id,
                            before.core.next_redeem,
                        ),
                        amount: *amount,
                        online_charge,
                    };
                    let insertion = custody.maps().insert(
                        Map::Recovery,
                        leaf.key(),
                        model(leaf.leaf_value())?,
                    )?;
                    let charge = charge.as_ref().map(|c| UnloadChargeOriginalsV1 {
                        quote: &c.quote,
                        certificate_set: &c.certificates,
                    });
                    Step::Consuming(Box::new(proof(self.prepare_consuming(
                        &owner,
                        predecessor.as_ref().ok_or(state::Error::FoldRequired)?,
                        ConsumingActionV1::Unload {
                            amount: *amount,
                            insertion: &insertion,
                            charge,
                        },
                        nonce,
                    ))?))
                }
                Action::Retire => Step::Consuming(Box::new(proof(self.prepare_consuming(
                    &owner,
                    predecessor.as_ref().ok_or(state::Error::FoldRequired)?,
                    ConsumingActionV1::Retiring,
                    nonce,
                ))?)),
            }
        };
        Ok(PreparedOperationV1 {
            owner,
            predecessor,
            step,
            send_usage,
        })
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn prepared_binding_changes_with_plan_bytes_source_and_installation() {
        let bound = PreparedBindingV1::new(b"exact choices", [1; 32], [2; 32]);
        assert!(bound == PreparedBindingV1::new(b"exact choices", [1; 32], [2; 32]));
        for changed in [
            PreparedBindingV1::new(b"exact choiceS", [1; 32], [2; 32]),
            PreparedBindingV1::new(b"exact choices ", [1; 32], [2; 32]),
            PreparedBindingV1::new(b"exact choices", [3; 32], [2; 32]),
            PreparedBindingV1::new(b"exact choices", [1; 32], [3; 32]),
        ] {
            assert!(bound != changed);
        }
    }

    #[test]
    fn proof_mapping_keeps_original_read_refusal_and_semantic_verdicts() {
        let bytes = norito::encode_canonical(&vec![7u8; 128]).unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let captured = norito::with_decode_limits_scope(limits, || {
            norito::decode_canonical_for_admission::<Vec<u8>>(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
        })
        .unwrap_err()
        .into_local_refusal()
        .unwrap();
        let expected = captured.clone();
        let error = proof::<()>(Err(Error::DecodeResource(captured))).unwrap_err();
        assert!(matches!(error, state::Error::DecodeResource(original) if original == expected));
        assert!(matches!(
            proof::<()>(Err(Error::Cancelled)),
            Err(state::Error::Cancelled)
        ));
        assert!(matches!(
            proof::<()>(Err(Error::Authority)),
            Err(state::Error::Proof(
                "installed native operation preparation"
            ))
        ));
    }

    #[test]
    fn load_receipt_dispatch_preserves_actual_decode_refusal_and_retry() {
        let fixture: norito::json::Value = norito::json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/kagemusha/ordinary_load_receipt_v1.json"
        )))
        .unwrap();
        let bytes = hex::decode(fixture["receipt_frame_hex"].as_str().unwrap()).unwrap();
        let expected = load_receipt_original(&bytes).unwrap();
        let unchanged = bytes.clone();
        let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
        let error =
            norito::with_decode_limits_scope(limits, || load_receipt_original(&bytes)).unwrap_err();
        assert!(matches!(error, state::Error::DecodeResource(ref original)
            if original.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(bytes, unchanged);
        assert_eq!(load_receipt_original(&bytes).unwrap(), expected);
        assert!(matches!(
            load_receipt_original(&[0]),
            Err(state::Error::Invalid(_))
        ));
    }

    #[test]
    fn native_original_decoder_preserves_local_refusal_and_invalid_input() {
        let value = vec![7u8; 128];
        let bytes = norito::encode_canonical(&value).unwrap();
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let error =
            norito::with_decode_limits_scope(limits, || decode::<Vec<u8>>(&bytes, bytes.len()))
                .unwrap_err();
        assert!(matches!(error, state::Error::DecodeResource(ref cause)
            if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
        assert_eq!(decode::<Vec<u8>>(&bytes, bytes.len()).unwrap(), value);
        assert!(matches!(
            decode::<Vec<u8>>(&[0], bytes.len()),
            Err(state::Error::Invalid(_))
        ));
    }

    #[test]
    fn native_preparation_mapping_preserves_cancellation_and_artifact_unavailability() {
        assert_eq!(proof(Ok(7)).unwrap(), 7);
        assert!(matches!(
            proof::<()>(Err(Error::Cancelled)),
            Err(state::Error::Cancelled)
        ));
        assert!(matches!(
            proof::<()>(Err(Error::Unavailable)),
            Err(state::Error::ArtifactsUnavailable(
                "native operation artifact"
            ))
        ));
        for rejected in [
            Error::Authority,
            Error::RuntimeBinding,
            Error::Inventory,
            Error::Profile,
            Error::Proof,
        ] {
            assert!(matches!(
                proof::<()>(Err(rejected)),
                Err(state::Error::Proof(
                    "installed native operation preparation"
                ))
            ));
        }
    }
}
