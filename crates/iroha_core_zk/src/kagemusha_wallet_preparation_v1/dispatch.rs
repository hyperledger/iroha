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
        Error::Unavailable => state::Error::ArtifactsUnavailable("native operation artifact"),
        Error::Cancelled => state::Error::Cancelled,
        _ => state::Error::Proof("installed native operation preparation"),
    })
}

fn model<T>(result: core::result::Result<T, KagemushaWalletValidationErrorV1>) -> Result<T> {
    result.map_err(|_| state::Error::Invalid("native operation original"))
}
fn decode<T>(bytes: &[u8], maximum: usize) -> Result<T>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(state::Error::Invalid("native original frame bound"));
    }
    norito::decode_canonical_with_limits(bytes, norito::canonical_decode_limits(bytes.len()))
        .map_err(|_| state::Error::Invalid("native original canonical frame"))
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
pub(crate) struct PreparedOperationV1 {
    owner: AuthenticatedCredentialV1,
    predecessor: Option<FoldedStateV1>,
    step: Step,
    send_usage: Option<KagemushaWalletQuotaUsageArrayV1>,
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
    blacklist: Option<KagemushaWalletBlacklistV1>,
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
            blacklist: send.blacklist.as_ref(),
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
            Step::Archive(_) => 12,
            Step::Monetary(s) => match s.statement().effect.kind() {
                K::Send => {
                    2 + u8::try_from(s.relation().enabled_controls())
                        .map_err(|_| state::Error::Invalid("Send control selector"))?
                }
                K::Receive => 10 + u8::from(s.request().body.receiver_blacklist_version != 0),
                _ => return Err(state::Error::Invalid("monetary selector")),
            },
            Step::Refresh(_) => 14,
            Step::Consuming(s) => match s.statement().effect.kind() {
                K::Unload => 13,
                K::Retiring => 15,
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
        let blacklist = if before.enforces_blacklist() {
            Some(model(KagemushaWalletBlacklistV1::decode_canonical(
                &required_original(custody, Original::Blacklist)?,
                &scheme.scheme_id(),
            ))?)
        } else {
            None
        };
        let share = if before.is_active(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1) {
            Some(model(KagemushaWalletQuotaShareV1::decode_canonical(
                &required_original(custody, Original::QuotaShare)?,
                &scheme.scheme_id(),
            ))?)
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
                blacklist,
                share,
                usage: *usage,
                charges: original.quota_charges.clone(),
                successor_usage: original.quota_usage,
            })),
        })
    }

    /// Import one strict original, prove the exact derived witness, and fully verify
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

    pub(crate) fn verify_frozen(
        &self,
        preparation: &PreparationV1<'_>,
        frozen: &state::FrozenTransition,
        budget: MemoryBudget,
    ) -> Result<()> {
        let expected = self.freeze(preparation, frozen.capsule.step_proof.clone(), budget)?;
        if &expected != frozen {
            return Err(state::Error::Proof(
                "prepared capsule differs from native derivation",
            ));
        }
        Ok(())
    }

    fn freeze(
        &self,
        preparation: &PreparationV1<'_>,
        sigma: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<state::FrozenTransition> {
        match &self.step {
            Step::Load(s) => proof(preparation.freeze_load(&self.owner, s, sigma, budget)),
            Step::Archive(s) => proof(preparation.freeze_archive(&self.owner, s, sigma, budget)),
            Step::Monetary(s) => proof(preparation.freeze_monetary(
                &self.owner,
                s,
                self.predecessor.as_ref(),
                sigma,
                budget,
            )),
            Step::Refresh(s) => proof(preparation.freeze_refresh(&self.owner, s, sigma, budget)),
            Step::Consuming(s) => proof(
                preparation.freeze_consuming(
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

impl PreparationV1<'_> {
    pub(crate) fn authenticate_credential_set(
        &self,
        credential: &[u8],
        certificates: &[u8],
    ) -> Result<AuthenticatedCredentialV1> {
        let scheme = self.installed.verifier().scheme();
        let current = model(KagemushaWalletCredentialV1::decode_canonical(
            credential,
            &scheme.scheme_id(),
        ))?;
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
    /// `nonce` and `now` are decoded from the already durable native plan on retries.
    pub(crate) fn prepare_operation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        sources: &QualifiedWalletSourcesV1,
        nonce: [u8; 32],
        now: Option<&KagemushaWalletMonotonicReadingV1>,
        budget: MemoryBudget,
    ) -> Result<PreparedOperationV1> {
        self.derive_operation(
            request,
            source,
            custody,
            sources,
            nonce,
            now,
            budget,
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
        sources: &QualifiedWalletSourcesV1,
        nonce: [u8; 32],
        now: Option<&KagemushaWalletMonotonicReadingV1>,
        budget: MemoryBudget,
    ) -> Result<PreparedOperationV1> {
        self.derive_operation(
            request,
            source,
            custody,
            sources,
            nonce,
            now,
            budget,
            Derivation::ReleasedFold,
            Some(frozen),
        )
    }

    fn derive_operation(
        &self,
        request: &NativeIntentV1,
        source: &PreparationSourceV1<'_>,
        custody: &mut PreparationCustodyV1<'_>,
        sources: &QualifiedWalletSourcesV1,
        nonce: [u8; 32],
        now: Option<&KagemushaWalletMonotonicReadingV1>,
        budget: MemoryBudget,
        derivation: Derivation,
        frozen: Option<&state::FrozenTransition>,
    ) -> Result<PreparedOperationV1> {
        let scheme = self.installed.verifier().scheme();
        if derivation == Derivation::BeforeAdvance {
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
        let before = &released.frozen.capsule.successor_state;
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
            let payment = model(KagemushaWalletPaymentV1::decode_canonical(
                &intent.payment,
                &scheme.scheme_id(),
            ))?;
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
                    let decoded = model(KagemushaWalletLoadReceiptV1::decode_canonical(receipt))?;
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
                        sources.finality(),
                        custody,
                        LoadOriginalsV1 {
                            receipt,
                            finality,
                            insertion: &insertion,
                        },
                        nonce,
                        budget,
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
                        None
                    } else {
                        let leaf = KagemushaWalletFeeClaimLeafV1 {
                            credit_id: request.credit_id(),
                            fee: request.body.fee,
                            fee_schedule_digest: request.body.fee_schedule,
                        };
                        Some(custody.maps().insert(
                            Map::Fee,
                            leaf.key(),
                            model(leaf.leaf_value())?,
                        )?)
                    };
                    let blacklist = if before.enforces_blacklist() {
                        Some(model(KagemushaWalletBlacklistV1::decode_canonical(
                            &required_original(custody, Original::Blacklist)?,
                            &scheme.scheme_id(),
                        ))?)
                    } else {
                        None
                    };
                    let share = if before.is_active(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1) {
                        Some(model(KagemushaWalletQuotaShareV1::decode_canonical(
                            &required_original(custody, Original::QuotaShare)?,
                            &scheme.scheme_id(),
                        ))?)
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
                    send_usage = Some(usage.clone());
                    let step = proof(self.prepare_send(
                        &owner,
                        predecessor.as_ref().ok_or(state::Error::FoldRequired)?,
                        original,
                        SendControlsV1 {
                            anchored: anchored.as_ref(),
                            now,
                            blacklist: blacklist.as_ref(),
                            quota_share: share.as_ref(),
                            quota_usage: &usage,
                        },
                        SendMapsV1 { pending, fee },
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
                        Derivation::BeforeAdvance => {
                            model(KagemushaWalletPaymentV1::decode_canonical(
                                payment,
                                &scheme.scheme_id(),
                            ))?
                        }
                        Derivation::ReleasedFold => {
                            decode(payment, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1)?
                        }
                    };
                    let frozen_request = frozen
                        .map(|frozen| {
                            let mut originals =
                                frozen.capsule.retained_inputs.iter().filter(|input| {
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
                    let digest = frozen_request
                        .map_or_else(|| decoded.request.request_digest(), |(digest, _)| digest);
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
                    let recorded = if request.body.receiver_blacklist_version == 0 {
                        None
                    } else {
                        let key = kagemusha_wallet_field_from_u128_v1(u128::from(
                            request.body.receiver_blacklist_version,
                        ));
                        let (history_leaf, history_opening) =
                            custody.maps().membership(Map::BlacklistHistory, &key)?;
                        Some(KagemushaWalletRecordedBlacklistProofV1 {
                            history_leaf,
                            history_opening,
                            gap: custody
                                .issued_request_gap(&digest)?
                                .ok_or(state::Error::WitnessLost("issued Request payer gap"))?,
                        })
                    };
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
                        Derivation::BeforeAdvance => self.prepare_receive(
                            &owner,
                            released,
                            &request_original,
                            payment,
                            payer_credential,
                            certificates,
                            recorded.as_ref(),
                            ReceiveMapsV1 { consumed },
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
                            recorded.as_ref(),
                            ReceiveMapsV1 { consumed },
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
                    let mut openings = Vec::new();
                    if *kind == KagemushaWalletPolicyUpdateKindV1::Blacklist {
                        let list = model(KagemushaWalletBlacklistV1::decode_canonical(
                            update,
                            &scheme.scheme_id(),
                        ))?;
                        let leaf = KagemushaWalletBlacklistHistoryLeafV1 {
                            list_version: list.body.list_version,
                            entries_root: list.body.entries_root,
                        };
                        let insertion = custody.maps().insert(
                            Map::BlacklistHistory,
                            leaf.key(),
                            model(leaf.leaf_value())?,
                        )?;
                        openings = vec![
                            insertion.low_opening.leaf_transcript(&insertion.low),
                            insertion.slot_opening.empty_transcript(),
                        ];
                    }
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
                            openings: &openings,
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
                        KagemushaWalletPolicyUpdateKindV1::Blacklist => Original::Blacklist,
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
                        let share = model(KagemushaWalletQuotaShareV1::decode_canonical(
                            update,
                            &scheme.scheme_id(),
                        ))?;
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
                            model(KagemushaWalletChargeQuoteV1::decode_canonical(
                                &original.quote,
                                &scheme.scheme_id(),
                            ))?
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
