//! Exact original admission and witnesses of the existing Send/Receive sigma engine.

use iroha_kagemusha_proof::{
    a_relation::native::{receive as native_receive, send as native_send},
    controls::{QuotaCharge, QuotaWitness, WindowSegment, WindowSlot},
    proof::SigmaProver,
    tree::{IndexedInsert, IndexedLeaf, QuotaWindow, QuotaWindowTree},
    witness::{
        Controls, CoreState, Identity, LineageInputs, MapRoots, ReceiveInputs, RequestBody,
        RequestTerms, SendInputs, SigmaRelation, StateRest, StateV1, StepInputs, StepWitness,
    },
};
use iroha_pasta::Eq;
use iroha_plonk::{ProverConfig, ProverRandomness};

use super::*;
#[path = "monetary/incoming_original.rs"]
mod incoming_original;

#[cfg(test)]
#[path = "monetary/tests.rs"]
mod tests;

/// Actual local control objects/time observations, selected by Native's durable source owner.
/// Original custody and OS monotonic observation authority remain with that owner. There is
/// no periodic issuer or Integrity request, acceptance flag, alternate clock or caller root.
pub struct SendControlsV1<'a> {
    /// Committed same-boot anchor, when held.
    pub anchored: Option<&'a KagemushaWalletAnchoredTimeV1>,
    /// Actual Native monotonic observation, mandatory for a held time anchor.
    /// The no-anchor floor-only path has no observation.
    pub now: Option<&'a KagemushaWalletMonotonicReadingV1>,
    /// Locally installed blacklist: the payer refuses a listed receiver before the
    /// irreversible debit. Never a state, proof or peer input.
    pub blacklist: Option<&'a KagemushaWalletBlacklistV1>,
    /// Held signed quota share including all original windows.
    pub quota_share: Option<&'a KagemushaWalletQuotaShareV1>,
    /// Exact current aligned array, authenticated by the source state's root.
    pub quota_usage: &'a KagemushaWalletQuotaUsageArrayV1,
}

/// Actual depth32 local insertions for a Send, consumed in the fixed production map rules.
#[derive(Clone, Copy, Debug)]
pub struct SendMapsV1 {
    /// Pending descriptor insertion against Omega's lineage-adjusted pending root.
    pub pending: KagemushaWalletIndexedInsertV1,
    /// Actual insertion or authenticated unchanged fee-map witness, selected by the Request.
    pub fee: SendFeeMapV1,
}

/// Source-owned fee-map witness for Send's fixed conditional insertion circuit.
#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "both variants are bounded depth32 witness DATA moved into one native preparation"
)]
pub enum SendFeeMapV1 {
    /// Actual insertion when the authenticated Request charges a nonzero fee.
    Insert(KagemushaWalletIndexedInsertV1),
    /// Actual existing leaf and path when the authenticated Request charges zero.
    /// Both circuit paths use this same opening; even a no-op authenticates its root.
    Preserve {
        /// Existing member or low leaf from the selected predecessor fee map.
        leaf: KagemushaWalletIndexedLeafV1,
        /// Exact depth32 opening against the selected predecessor fee root.
        opening: KagemushaWalletIndexedOpeningV1,
    },
}

/// Exact consumed-credit insertion for a Receive; duplicate admission fails before Advance.
#[derive(Clone, Copy, Debug)]
pub struct ReceiveMapsV1 {
    /// Insertion against the current selected source state's consumed root.
    pub consumed: KagemushaWalletIndexedInsertV1,
}

/// A prepared real sigma witness and derived canonical G1 successor/statement.
/// Private construction retains the exact originals and map witnesses used in preparation.
/// This supplies proof generation input; only the custody coordinator can release Advance.
pub struct MonetaryStepV1 {
    manifest_digest: [u8; 32],
    source_capsule_digest: [u8; 32],
    relation: SigmaRelation,
    witness: StepWitness<Fp>,
    state: KagemushaWalletStateV1,
    statement: KagemushaWalletStatementV1,
    request: KagemushaWalletRequestV1,
    request_original: Vec<u8>,
    payment_original: Option<Vec<u8>>,
    maps: Vec<IndexedInsert<Fp>>,
    // Reconstructed from the authenticated predecessor fee map on every preparation/replay.
    // A no-op is fold input only: it must never add an insertion to the durable capsule.
    send_fee_witness: Option<IndexedInsert<Fp>>,
    send_check: Option<KagemushaWalletSendCheckV1>,
    payer: Option<PayerOriginalV1>,
    payer_certificate_set_original: Option<Vec<u8>>,
}

// Exact incoming signed bytes, deliberately not an authenticated credential capability.
struct PayerOriginalV1 {
    credential_original: Vec<u8>,
    credential_tape: Vec<u8>,
}
impl From<AuthenticatedCredentialV1> for PayerOriginalV1 {
    fn from(owner: AuthenticatedCredentialV1) -> Self {
        Self {
            credential_original: owner.credential_original,
            credential_tape: owner.credential_tape,
        }
    }
}

impl MonetaryStepV1 {
    /// Authenticated installation to recheck before capsule freezing and commit.
    #[must_use]
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    pub(super) fn capsule_inputs(&self) -> Result<Vec<KagemushaWalletRetainedInputV1>, Error> {
        use KagemushaWalletRetainedInputRoleV1 as R;
        let mut inputs = vec![KagemushaWalletRetainedInputV1 {
            role: R::Request,
            bytes: self.request_original.clone(),
        }];
        if self.statement.effect.kind() == KagemushaWalletOperationKindV1::Receive {
            inputs.extend([
                KagemushaWalletRetainedInputV1 {
                    role: R::Payment,
                    bytes: self.payment_original.clone().ok_or(Error::Authority)?,
                },
                KagemushaWalletRetainedInputV1 {
                    role: R::CertificateSet,
                    bytes: self
                        .payer_certificate_set_original
                        .clone()
                        .ok_or(Error::Authority)?,
                },
                KagemushaWalletRetainedInputV1 {
                    role: R::Credential,
                    bytes: self
                        .payer
                        .as_ref()
                        .ok_or(Error::Authority)?
                        .credential_original
                        .clone(),
                },
            ]);
        } else if self.payment_original.is_some()
            || self.payer.is_some()
            || self.payer_certificate_set_original.is_some()
        {
            return Err(Error::Authority);
        }
        Ok(inputs)
    }

    pub(super) fn retained_payment_digest(&self) -> Result<[u8; 32], Error> {
        match self.payment_original.as_deref() {
            None => Ok([0; 32]),
            Some(bytes) => Ok(incoming_original::payment(bytes)?.payment_digest),
        }
    }

    /// Exact witness of the installed selector; not a separate monetary relation.
    #[must_use]
    pub const fn witness(&self) -> &StepWitness<Fp> {
        &self.witness
    }
    /// Selector fixed by the source controls (Send); Receive has one selector.
    #[must_use]
    pub const fn relation(&self) -> SigmaRelation {
        self.relation
    }
    /// Derived successor, with every root/state field checked against the native evaluator.
    #[must_use]
    pub const fn state(&self) -> &KagemushaWalletStateV1 {
        &self.state
    }
    /// Derived exact statement used in the proof and later source capsule.
    #[must_use]
    pub const fn statement(&self) -> &KagemushaWalletStatementV1 {
        &self.statement
    }
    /// Authenticated exact Request frame and optional exact received Payment frame.
    #[must_use]
    pub fn originals(&self) -> (&[u8], Option<&[u8]>) {
        (&self.request_original, self.payment_original.as_deref())
    }
    /// Exact signed Request for session retention and signature/Q tape preparation.
    #[must_use]
    pub const fn request(&self) -> &KagemushaWalletRequestV1 {
        &self.request
    }
    /// Canonical actual insertions: pending and a positive fee, or consumed.
    /// A zero-fee fold opening is transient and is never a durable map insertion.
    #[must_use]
    pub fn map_witnesses(&self) -> &[IndexedInsert<Fp>] {
        &self.maps
    }
    /// Actual model-derived Send interval/charges/successor usage for durable retention.
    #[must_use]
    pub const fn send_check(&self) -> Option<&KagemushaWalletSendCheckV1> {
        self.send_check.as_ref()
    }
    /// Exact source capsule to recheck at commit under the Native head lock.
    #[must_use]
    pub const fn source_capsule_digest(&self) -> [u8; 32] {
        self.source_capsule_digest
    }
}

fn word(bytes: [u8; 32]) -> Result<Fp, Error> {
    fields::<1>(vec![bytes]).map(|words| words[0])
}

/// One completed Request original, verified under `scheme`.
fn request(
    original: &[u8],
    scheme: &KagemushaWalletSchemeV1,
) -> Result<KagemushaWalletRequestV1, Error> {
    let request = decode_request(original)?;
    authority(request.verify(scheme))?;
    Ok(request)
}

/// The receiver's Request completed for `payer` at `send_ordinal`: an open Request is completed,
/// a completed one must already be exactly that completion.
fn payer_request(
    original: &[u8],
    scheme: &KagemushaWalletSchemeV1,
    payer: &KagemushaWalletCredentialV1,
    send_ordinal: u128,
) -> Result<KagemushaWalletRequestV1, Error> {
    let request = authority(decode_request(original)?.complete(payer, send_ordinal))?;
    authority(request.verify(scheme))?;
    Ok(request)
}

fn decode_request(original: &[u8]) -> Result<KagemushaWalletRequestV1, Error> {
    if original.is_empty() || original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Error::Authority);
    }
    read_original(|| {
        norito::decode_canonical_with_limits(
            original,
            norito::canonical_decode_limits(original.len()),
        )
    })
}

fn request_fields(body: &KagemushaWalletRequestBodyV1) -> Result<RequestBody, Error> {
    authority(body.validate())?;
    let out = RequestBody {
        scheme_id: body.scheme_id,
        asset_digest: body.asset_digest,
        payer_wallet: body.payer_wallet_id,
        payer_account: body.payer_account_digest,
        receiver_wallet: body.receiver_wallet_id,
        receiver_account: body.receiver_account_digest,
        send_ordinal: body.send_ordinal,
        receiver_credential_digest: body.receiver_credential_digest,
        terms: RequestTerms {
            amount: body.amount,
            fee: body.fee,
            fee_schedule: body.fee_schedule,
            policy_epoch: body.policy_epoch,
            scheme_policy: body.scheme_policy,
            request_time: body.receiver_accepted_time_ms,
            certificates: body.certificates,
            nonce: body.nonce,
        },
    };
    if out.fields::<Fp>() != fields::<24>(body.field_items())? {
        return Err(Error::Authority);
    }
    Ok(out)
}

fn state_fields(state: &KagemushaWalletStateV1) -> Result<StateV1<Fp>, Error> {
    authority(state.validate())?;
    let c = &state.core;
    let r = &state.rest;
    let out = StateV1 {
        core: CoreState {
            lifecycle: c.lifecycle.tag(),
            identity: Identity {
                scheme_id: c.scheme_id,
                asset_digest: c.asset_digest,
                wallet_id: c.wallet_id,
                credential_digest: c.credential_digest,
            },
            balance: c.balance,
            burned_total: c.burned_total,
            sequence: c.sequence,
            next_send: c.next_send,
            next_load: c.next_load,
            next_redeem: c.next_redeem,
            send_chain: word(c.send_chain)?,
            recv_chain: word(c.recv_chain)?,
            roots: MapRoots {
                consumed_credit: word(c.consumed_credit_root)?,
                pending_outgoing: word(c.pending_outgoing_root)?,
                load_redeem_recovery: word(c.load_redeem_recovery_root)?,
                fee_claim_recovery: word(c.fee_claim_root)?,
                quota_usage: word(c.quota_usage_root)?,
            },
            controls: Controls {
                enabled: c.enabled_controls,
                quota_windows_root: word(c.quota_windows_root)?,
                quota_share_expires_at_ms: c.quota_share_expires_at_ms,
                time_anchor_max_response_ms: c.time_anchor_max_response_ms,
                lease_expires_at_ms: c.lease_expires_at_ms,
            },
            policy_epoch: c.policy_epoch,
            accepted_time_floor_ms: c.accepted_time_floor_ms,
            state_nonce: word(c.state_nonce)?,
        },
        rest: StateRest {
            permitted_controls: r.permitted_controls,
            scheme_policy: r.scheme_policy,
            fee_schedule: r.fee_schedule,
            quota_share: r.quota_share,
            quota_share_id: r.quota_share_id,
            time_anchor: r.time_anchor,
        },
    };
    if out.core.fields() != fields::<29>(authority(state.core_field_items())?)?
        || out.rest.fields::<Fp>() != fields::<6>(authority(state.rest_field_items())?)?
        || out.commitment().to_repr() != authority(state.commitment())?.value
    {
        return Err(Error::Authority);
    }
    Ok(out)
}

pub(super) fn insertion(
    witness: &KagemushaWalletIndexedInsertV1,
) -> Result<IndexedInsert<Fp>, Error> {
    authority(witness.low.validate())?;
    // Preserve every actual path; verification of its exact key/value/root precedes conversion.
    Ok(IndexedInsert {
        leaf: IndexedLeaf {
            key: word(witness.low.key)?,
            value: word(witness.low.value)?,
            next_key: word(witness.low.next_key)?,
        },
        leaf_slot: witness.low_opening.slot,
        leaf_siblings: fields(witness.low_opening.siblings.to_vec())?,
        slot: witness.slot_opening.slot,
        slot_siblings: fields(witness.slot_opening.siblings.to_vec())?,
    })
}

fn window(window: &KagemushaWalletQuotaWindowV1) -> QuotaWindow {
    QuotaWindow {
        kind: window.kind.tag(),
        start_ms: window.start_ms,
        end_ms: window.end_ms,
        limit: window.limit,
    }
}

fn quota(
    relation: SigmaRelation,
    share: Option<&KagemushaWalletQuotaShareV1>,
    check: &KagemushaWalletSendCheckV1,
) -> Result<QuotaWitness<Fp>, Error> {
    if !relation.enforces(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1) {
        if !check.quota_charges.is_empty() {
            return Err(Error::Authority);
        }
        return Ok(QuotaWitness::unused());
    }
    let share = share.ok_or(Error::Authority)?;
    authority(share.validate())?;
    let windows: Vec<_> = share.windows.iter().map(window).collect();
    let tree = QuotaWindowTree::new(&windows).ok_or(Error::Authority)?;
    if tree.root::<Fp>().to_repr() != share.body.windows_root {
        return Err(Error::Authority);
    }
    let mut out = QuotaWitness::unused();
    let mut used_charges = 0;
    for (kind_index, kind) in [1, 2].into_iter().enumerate() {
        // First window of this kind not wholly before L, or the first higher-kind/padding slot.
        // Four actual consecutive slots prove both excluded boundaries in the existing circuit.
        let base = windows
            .iter()
            .position(|w| w.kind >= kind && (w.kind > kind || w.end_ms > check.interval.lower_ms))
            .unwrap_or(windows.len());
        let mut segment = WindowSegment::unused();
        segment.base = u8::try_from(base).map_err(|_| Error::Authority)?;
        for position in 0..4 {
            if segment.present(position) {
                let slot = usize::try_from(segment.slot(position)).map_err(|_| Error::Authority)?;
                segment.slots[position] = WindowSlot {
                    window: tree.slot(slot),
                    siblings: tree.siblings(slot),
                };
            }
        }
        for position in [1, 2] {
            let candidate = &segment.slots[position];
            if segment.present(position)
                && candidate.window.kind == kind
                && candidate
                    .window
                    .touches(check.interval.lower_ms, check.interval.upper_ms)
            {
                let slot = u8::try_from(segment.slot(position)).map_err(|_| Error::Authority)?;
                let charge = check
                    .quota_charges
                    .get(used_charges)
                    .ok_or(Error::Authority)?;
                if charge.slot() != slot || window(&charge.window) != candidate.window {
                    return Err(Error::Authority);
                }
                out.charges[kind_index * 2 + position - 1] = QuotaCharge {
                    slot,
                    used: charge.usage.used,
                    siblings: fields(charge.usage_opening.siblings.to_vec())?,
                };
                used_charges += 1;
            }
        }
        out.segments[kind_index] = segment;
    }
    if used_charges != check.quota_charges.len() {
        return Err(Error::Authority);
    }
    Ok(out)
}

fn successor(
    source: &KagemushaWalletStateV1,
    native: &StateV1<Fp>,
) -> Result<KagemushaWalletStateV1, Error> {
    let mut out = *source;
    let c = &mut out.core;
    // The same existing evaluator derives all core fields. Carrying the source's rest/identity
    // is checked again by complete array equality, so no changed field can be silently omitted.
    c.lifecycle = match native.core.lifecycle {
        1 => KagemushaWalletLifecycleV1::Active,
        2 => KagemushaWalletLifecycleV1::Retiring,
        _ => return Err(Error::Authority),
    };
    c.balance = native.core.balance;
    c.burned_total = native.core.burned_total;
    c.sequence = native.core.sequence;
    c.next_send = native.core.next_send;
    c.send_chain = native.core.send_chain.to_repr();
    c.recv_chain = native.core.recv_chain.to_repr();
    c.consumed_credit_root = native.core.roots.consumed_credit.to_repr();
    c.pending_outgoing_root = native.core.roots.pending_outgoing.to_repr();
    c.fee_claim_root = native.core.roots.fee_claim_recovery.to_repr();
    c.quota_usage_root = native.core.roots.quota_usage.to_repr();
    c.accepted_time_floor_ms = native.core.accepted_time_floor_ms;
    c.state_nonce = native.core.state_nonce.to_repr();
    if state_fields(&out)? != *native {
        return Err(Error::Authority);
    }
    Ok(out)
}

fn derive(
    source: &KagemushaWalletStateV1,
    relation: SigmaRelation,
    witness: &StepWitness<Fp>,
    effect: KagemushaWalletEffectV1,
) -> Result<(KagemushaWalletStateV1, KagemushaWalletStatementV1), Error> {
    let native = witness.evaluate(relation);
    if !native.is_honest() {
        return Err(Error::Authority);
    }
    let state = successor(source, &native.successor_state.ok_or(Error::Authority)?)?;
    let lineage = match &witness.inputs {
        StepInputs::Send(input) => (
            input.lineage.burned_total,
            input.lineage.pending_outgoing_root.to_repr(),
        ),
        StepInputs::Receive(_) => (0, [0; 32]),
    };
    let statement = KagemushaWalletStatementV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: state.core.scheme_id,
        relation_id: witness.relation_id,
        credential_digest: state.core.credential_digest,
        asset_digest: state.core.asset_digest,
        lifecycle: state.core.lifecycle,
        sequence: state.core.sequence,
        next_load: state.core.next_load,
        // Receive has one sigma selector; the statement still carries the predecessor's
        // complete control mask.
        enabled_controls: source.core.enabled_controls,
        lineage_burned_total: lineage.0,
        lineage_pending_outgoing_root: lineage.1,
        predecessor: authority(source.commitment())?,
        successor: authority(state.commitment())?,
        effect,
    };
    if fields::<26>(authority(statement.field_items())?)? != native.statement
        || authority(statement.statement_digest())? != native.digests.statement.to_repr()
    {
        return Err(Error::Authority);
    }
    Ok((state, statement))
}

/// Verified original field projection; Q proofs remain mandatory independent inputs.
pub struct SendFoldFieldsV1 {
    pub(crate) state: native_send::SendState,
    /// The prepared step witness whose relation A1 proves inline.
    pub(crate) step: StepWitness<Fp>,
    pub(crate) objects: [Vec<u8>; 4],
    pub(crate) pending: IndexedInsert<Fp>,
    pub(crate) fee: IndexedInsert<Fp>,
    pub(crate) predecessor: native_send::PredecessorInput,
}
impl SendFoldFieldsV1 {
    pub(crate) fn with_q(self, q: [native_send::QInput; 1]) -> native_send::Inputs {
        native_send::Inputs {
            state: self.state,
            step: self.step,
            objects: self.objects,
            pending: self.pending,
            fee: self.fee,
            predecessor: self.predecessor,
            q,
        }
    }
}

/// Exact Receive originals before any burn or permanent credit-record proposal.
pub struct ReceiveSourceFieldsV1 {
    pub(crate) before: StateWitness,
    pub(crate) after: StateWitness,
    pub(crate) statement: [Fp; 26],
    /// The prepared step witness whose relation A1 proves inline.
    pub(crate) step: StepWitness<Fp>,
    pub(crate) consumed: IndexedInsert<Fp>,
    pub(crate) incoming_statement: [Fp; 26],
    pub(crate) objects: [Vec<u8>; 9],
    /// Native source of the payment key for the own-receipt slot; not a circuit object.
    pub(crate) credential: Vec<u8>,
    pub(crate) predecessor: native_receive::PredecessorInput,
}

/// Verified original field projection; Q proofs remain mandatory independent inputs.
pub struct ReceiveFoldFieldsV1 {
    pub(crate) transition: native_receive::Transition,
    pub(crate) incoming_statement: [Fp; 26],
    pub(crate) step: StepWitness<Fp>,
    pub(crate) objects: [Vec<u8>; 9],
    /// Native source of the payment key for the own-receipt slot; not a circuit object.
    pub(crate) credential: Vec<u8>,
    pub(crate) incoming: native_receive::IncomingWitness,
    pub(crate) predecessor: native_receive::PredecessorInput,
}
impl ReceiveFoldFieldsV1 {
    pub(crate) fn with_q(self, q: [native_receive::QInput; 2]) -> native_receive::Inputs {
        native_receive::Inputs {
            transition: self.transition,
            incoming_statement: self.incoming_statement,
            step: self.step,
            objects: self.objects,
            incoming: self.incoming,
            predecessor: self.predecessor,
            q,
        }
    }
}

impl PreparationV1<'_> {
    // The review and real Send producer share this complete original admission and whole
    // control check. It derives no nonce, insertion, proof, signature or successor.
    pub(crate) fn review_send_terms(
        &self,
        owner: &AuthenticatedCredentialV1,
        predecessor: &FoldedStateV1,
        request_original: &[u8],
        controls: &SendControlsV1<'_>,
    ) -> Result<(KagemushaWalletRequestV1, KagemushaWalletSendCheckV1), Error> {
        self.credential_owner(owner)?;
        if predecessor.manifest_digest != self.installed.verifier().manifest_digest()
            || predecessor.credential != owner.credential
        {
            return Err(Error::Authority);
        }
        let request = payer_request(
            request_original,
            self.installed.verifier().scheme(),
            &owner.credential,
            predecessor.source_state.core.next_send,
        )?;
        let check = authority(request.check_send(&KagemushaWalletSendInputsV1 {
            payer_credential: &owner.credential,
            payer_state: &predecessor.source_state,
            omega: &predecessor.lineage.public,
            anchored: controls.anchored,
            now: controls.now,
            blacklist: controls.blacklist,
            quota_share: controls.quota_share,
            quota_usage: controls.quota_usage,
        }))?;
        Ok((request, check))
    }

    /// Derive a Send sigma witness from the authenticated folded source, exact signed Request,
    /// actual local controls and actual map insertions. The existing G1/native engines derive
    /// every effect and successor; hardware preparation approval/head-lock/Advance remain Native.
    /// # Errors
    /// Foreign source/Request, failed existing Send rules, invalid map/control path or parity.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_send(
        &self,
        owner: &AuthenticatedCredentialV1,
        predecessor: &FoldedStateV1,
        request_original: &[u8],
        controls: &SendControlsV1<'_>,
        maps: &SendMapsV1,
        successor_nonce: [u8; 32],
    ) -> Result<MonetaryStepV1, Error> {
        let (request, check) =
            self.review_send_terms(owner, predecessor, request_original, controls)?;
        let scheme = self.installed.verifier().scheme();
        let source = &predecessor.source_state;
        let body = request_fields(&request.body)?;
        let pending = KagemushaWalletPendingOutgoingLeafV1 {
            credit_id: request.credit_id(),
            receiver_wallet_id: request.body.receiver_wallet_id,
            send_ordinal: request.body.send_ordinal,
            amount: request.body.amount,
            fee: request.body.fee,
            request_digest: request.request_digest(),
        };
        let pending_root = authority(maps.pending.verify(
            &predecessor.lineage.public.pending_outgoing_root,
            &pending.key(),
            &authority(pending.leaf_value())?,
        ))?;
        let (fee_root, fee_witness) = send_fee_map(
            &source.core.fee_claim_root,
            KagemushaWalletFeeClaimLeafV1 {
                credit_id: pending.credit_id,
                fee: request.body.fee,
                fee_schedule_digest: request.body.fee_schedule,
            },
            &maps.fee,
        )?;
        let relation = SigmaRelation::send(source.core.enabled_controls);
        let witness = StepWitness {
            relation_id: scheme.relation_id,
            predecessor: state_fields(source)?,
            successor_nonce: word(successor_nonce)?,
            inputs: StepInputs::Send(Box::new(SendInputs {
                payer_account_digest: body.payer_account,
                receiver_wallet: body.receiver_wallet,
                receiver_account_digest: body.receiver_account,
                receiver_credential_digest: body.receiver_credential_digest,
                request: body.terms,
                request_digest: request.request_digest(),
                accepted_lower: check.interval.lower_ms,
                accepted_upper: check.interval.upper_ms,
                lineage: LineageInputs {
                    burned_total: predecessor.lineage.public.burned_total,
                    pending_outgoing_root: word(predecessor.lineage.public.pending_outgoing_root)?,
                },
                successor_pending_outgoing: word(pending_root)?,
                successor_fee_claim: word(fee_root)?,
                quota: Box::new(quota(relation, controls.quota_share, &check)?),
            })),
        };
        if witness.request_body() != body {
            return Err(Error::Authority);
        }
        let (state, statement) = derive(source, relation, &witness, check.effect)?;
        if state.core.quota_usage_root != check.quota_usage.root() {
            return Err(Error::Authority);
        }
        authority(statement.validate_for_scheme(scheme))?;
        authority(statement.validate_for_credential(&owner.credential))?;
        authority(statement.validate_successor_of(&predecessor.source_statement))?;
        authority(statement.validate_against_lineage(&predecessor.lineage.public))?;
        let native_maps = send_insertions(&maps.pending, request.body.fee, &fee_witness)?;
        Ok(MonetaryStepV1 {
            manifest_digest: owner.manifest_digest,
            source_capsule_digest: predecessor.source_capsule_digest,
            relation,
            witness,
            state,
            statement,
            // The completed Request, whatever form the caller passed: the Send capsule, its
            // Archive and every fold retain this payer's completion.
            request_original: norito::encode_canonical(&request).map_err(|_| Error::Authority)?,
            request,
            payment_original: None,
            maps: native_maps,
            send_fee_witness: Some(fee_witness),
            send_check: Some(check),
            payer: None,
            payer_certificate_set_original: None,
        })
    }

    /// Derive Receive from the actual selected current source, retained issued Request and
    /// exact Payment plus issuer originals. It does not require a receiver folded head.
    /// Current and quoted credential digests may differ while stable wallet/account/key hold.
    /// # Errors
    /// Invalid original/signature/native incoming proof, a payer on the local blacklist
    /// ([`Error::Blocked`]) or consumed insertion.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_receive(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        request_original: &[u8],
        payment_original: &[u8],
        payer_credential_original: &[u8],
        payer_certificate_set_original: &[u8],
        blacklist: Option<&KagemushaWalletBlacklistV1>,
        maps: &ReceiveMapsV1,
        successor_nonce: [u8; 32],
        budget: MemoryBudget,
    ) -> Result<MonetaryStepV1, Error> {
        self.receipt_tape(owner, source, budget)?;
        let scheme = self.installed.verifier().scheme();
        let request = request(request_original, scheme)?;
        let payment = read_model(|| {
            KagemushaWalletPaymentV1::decode_canonical(payment_original, &scheme.scheme_id())
        })?;
        let payer = read_model(|| {
            KagemushaWalletCredentialV1::decode_canonical(
                payer_credential_original,
                &scheme.scheme_id(),
            )
        })?;
        if payer_certificate_set_original.is_empty()
            || payer_certificate_set_original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        {
            return Err(Error::Authority);
        }
        let certificates: KagemushaWalletCertificateSetV1 = read_original(|| {
            norito::decode_canonical_with_limits(
                payer_certificate_set_original,
                norito::canonical_decode_limits(payer_certificate_set_original.len()),
            )
        })?;
        let source_state = &source.frozen.capsule.body().successor_state;
        let check = authority(payment.prepare_receive(
            scheme,
            &payer,
            &certificates,
            &request,
            &owner.credential,
            source_state,
            blacklist,
        ))?;
        let payer_certificate = authority(certificates.certificate(
            &payer.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        ))?;
        let payer_owner = self.authenticate_credential(
            payer_credential_original,
            &authority(payer_certificate.to_canonical_bytes())?,
        )?;
        // Genuine native proof verification includes sigma and the incoming Omega opening/P/V.
        // The post-Advance A producer remains the canonical total soft verifier/burn engine.
        self.installed
            .verifier()
            .verify_package_proofs_cancellable(&payment.send, budget, self.cancellation)?;
        self.derive_receive(
            owner,
            source,
            request,
            request_original,
            payment_original,
            payer_owner.into(),
            payer_certificate_set_original,
            maps,
            successor_nonce,
            check.effect,
        )
    }

    /// Restore only a selected Receive's own sigma witness. Incoming acceptance belongs
    /// to the total fold predicates; this private path never authorizes Advance or signing.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_receive(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        request_original: &[u8],
        payment_original: &[u8],
        payer_original: &[u8],
        payer_certificates: &[u8],
        maps: &ReceiveMapsV1,
        nonce: [u8; 32],
        budget: MemoryBudget,
    ) -> Result<MonetaryStepV1, Error> {
        self.receipt_tape(owner, source, budget)?;
        let request = request(request_original, self.installed.verifier().scheme())?;
        if request.body.receiver_wallet_id != owner.credential.body.wallet_id
            || request.receiver_credential.body.payment_key != owner.credential.body.payment_key
            || request.body.receiver_account_digest != owner.credential.body.account_digest
        {
            return Err(Error::Authority);
        }
        if payer_original.is_empty()
            || payer_original.len() > KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1
        {
            return Err(Error::Authority);
        }
        let credential: KagemushaWalletCredentialV1 = read_original(|| {
            norito::decode_canonical_with_limits(
                payer_original,
                norito::canonical_decode_limits(payer_original.len()),
            )
        })?;
        incoming_original::payment(payment_original)?;
        let payer = PayerOriginalV1 {
            credential_original: payer_original.to_vec(),
            credential_tape: signed_tape(credential.body.transcript(), &credential.signature),
        };
        let effect = KagemushaWalletEffectV1::Receive {
            credit_id: request.credit_id(),
            payer_wallet_id: request.body.payer_wallet_id,
            amount: request.body.amount,
        };
        self.derive_receive(
            owner,
            source,
            request,
            request_original,
            payment_original,
            payer,
            payer_certificates,
            maps,
            nonce,
            effect,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn derive_receive(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        request: KagemushaWalletRequestV1,
        request_original: &[u8],
        payment_original: &[u8],
        payer: PayerOriginalV1,
        payer_certificate_set_original: &[u8],
        maps: &ReceiveMapsV1,
        successor_nonce: [u8; 32],
        effect: KagemushaWalletEffectV1,
    ) -> Result<MonetaryStepV1, Error> {
        let scheme = self.installed.verifier().scheme();
        let source_state = &source.frozen.capsule.body().successor_state;
        let sequence = source_state
            .core
            .sequence
            .checked_add(1)
            .ok_or(Error::Authority)?;
        let consumed = KagemushaWalletConsumedCreditLeafV1 {
            credit_id: request.credit_id(),
            amount: request.body.amount,
            receive_sequence: sequence,
        };
        let consumed_root = authority(maps.consumed.verify(
            &source_state.core.consumed_credit_root,
            &consumed.key(),
            &authority(consumed.leaf_value())?,
        ))?;
        let body = request_fields(&request.body)?;
        let relation = SigmaRelation::RECEIVE;
        let witness = StepWitness {
            relation_id: scheme.relation_id,
            predecessor: state_fields(source_state)?,
            successor_nonce: word(successor_nonce)?,
            inputs: StepInputs::Receive(Box::new(ReceiveInputs {
                payer_wallet: body.payer_wallet,
                payer_account_digest: body.payer_account,
                receiver_account_digest: body.receiver_account,
                send_ordinal: body.send_ordinal,
                receiver_credential_digest: body.receiver_credential_digest,
                request: body.terms,
                successor_consumed_credit: word(consumed_root)?,
            })),
        };
        if witness.request_body() != body {
            return Err(Error::Authority);
        }
        let (state, statement) = derive(source_state, relation, &witness, effect)?;
        authority(statement.validate_for_scheme(scheme))?;
        authority(statement.validate_for_credential(&owner.credential))?;
        authority(statement.validate_successor_of(&source.frozen.capsule.body().statement))?;
        Ok(MonetaryStepV1 {
            manifest_digest: owner.manifest_digest,
            source_capsule_digest: source.frozen.capsule.custody_digest(),
            relation,
            witness,
            state,
            statement,
            request,
            request_original: request_original.to_vec(),
            payment_original: Some(payment_original.to_vec()),
            maps: vec![insertion(&maps.consumed)?],
            send_fee_witness: None,
            send_check: None,
            payer: Some(payer),
            payer_certificate_set_original: Some(payer_certificate_set_original.to_vec()),
        })
    }

    /// Prove the derived witness with the actual original-PK native component matching the
    /// installed signed selector/descriptor/VK, then fully self-verify under the caller budget.
    /// A preparation bound to a cancellation signal stops the prover at its next boundary.
    /// # Errors
    /// Another installation/component/source selector, failed proof or statement parity, or
    /// cancellation without a proof.
    pub fn prove_monetary_sigma(
        &self,
        step: &MonetaryStepV1,
        prover: &SigmaProver<Eq>,
        randomness: ProverRandomness,
        budget: MemoryBudget,
    ) -> Result<KagemushaWalletStepProofV1, Error> {
        if step.manifest_digest != self.installed.verifier().manifest_digest() {
            return Err(Error::Authority);
        }
        let verifier = prover.verifier();
        if verifier.relation() != step.relation {
            return Err(Error::Profile);
        }
        let (kind, mask) = step.relation.selector();
        let installed = self
            .installed
            .originals()
            .steps
            .iter()
            .find(|entry| entry.kind.tag() == kind && entry.enabled_controls == mask)
            .ok_or(Error::Inventory)?;
        if installed.artifact.descriptor != verifier.descriptor_bytes()
            || installed.artifact.verifying_key != verifier.vk_bytes()
        {
            return Err(Error::Profile);
        }
        // The same engine and randomness as an uncancellable proof; the signal only stops it.
        let proof = prover
            .prove_with_config(
                &step.witness,
                randomness,
                ProverConfig {
                    cancellation: self.cancellation,
                    ..ProverConfig::default()
                },
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        if proof.public.statement.to_repr() != authority(step.statement.statement_digest())?
            || proof.bytes.len() != verifier.proof_bytes().map_err(|_| Error::Profile)?
        {
            return Err(Error::Proof);
        }
        let _self_verification = iroha_plonk::work_metrics::WorkTimer::start(
            iroha_plonk::work_metrics::WorkPhase::SelfVerify,
        );
        iroha_plonk::verify_full(
            verifier.params(),
            verifier.binding(),
            verifier.vk(),
            &[vec![proof.public.statement]],
            &proof.bytes,
            budget,
        )
        .map_err(|_| Error::Proof)?;
        let step_proof = KagemushaWalletStepProofV1 { bytes: proof.bytes };
        authority(step_proof.validate())?;
        Ok(step_proof)
    }

    fn retained_monetary(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        prepared: &MonetaryStepV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<(StateWitness, [Fp; 26], Vec<u8>), Error> {
        let capsule = &step.frozen.capsule;
        if prepared.manifest_digest != self.installed.verifier().manifest_digest()
            || prepared.source_capsule_digest != predecessor.source_capsule_digest
            || prepared.statement != capsule.body().statement
            || prepared.state != capsule.body().successor_state
            || retained_original(
                &capsule.body().retained_inputs,
                KagemushaWalletRetainedInputRoleV1::Request,
            )? != prepared.request_original
        {
            return Err(Error::Authority);
        }
        self.transition_fields(owner, step, predecessor, public, budget)
    }

    /// Reconstruct Send's source before its independent Q proof exists, from the exact
    /// released source and preparation. Every subsequently attached Q original is
    /// fully verified by `native_send::Plan::prepare`.
    ///
    /// # Errors
    /// Changed source/head/originals/statement/credential or failed retained native proofs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn send_fold_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        prepared: &MonetaryStepV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<SendFoldFieldsV1, Error> {
        if prepared.statement.effect.kind() != KagemushaWalletOperationKindV1::Send
            || prepared.payment_original.is_some()
        {
            return Err(Error::Authority);
        }
        let (after, statement, receipt) =
            self.retained_monetary(owner, step, predecessor, prepared, public, budget)?;
        let fee = prepared.request.fee_schedule.schedule().map_or_else(
            || vec![0; KAGEMUSHA_WALLET_FEE_SCHEDULE_BODY_TRANSCRIPT_BYTES_V1 + 64],
            |fee| signed_tape(fee.body.transcript(), &fee.signature),
        );
        let pending = *prepared.maps.first().ok_or(Error::Authority)?;
        let fee_map = prepared.send_fee_witness.ok_or(Error::Authority)?;
        Ok(SendFoldFieldsV1 {
            state: native_send::SendState {
                before: predecessor.witness,
                after,
                statement,
            },
            // A1 proves this witness's relation; native prepare evaluates it to the
            // exact committed statement first. σ_send itself travels only in the Payment.
            step: prepared.witness.clone(),
            objects: [
                owner.credential_tape.clone(),
                signed_tape(
                    prepared.request.body.transcript(),
                    &prepared.request.signature,
                ),
                fee,
                receipt,
            ],
            pending,
            fee: fee_map,
            predecessor: native_send::PredecessorInput {
                proof: predecessor.proof.clone(),
                pallas: predecessor.pallas,
                vesta: predecessor.vesta,
            },
        })
    }

    /// Decode and authenticate original Receive source without selecting a credit burn branch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive_source_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        prepared: &MonetaryStepV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<ReceiveSourceFieldsV1, Error> {
        if prepared.statement.effect.kind() != KagemushaWalletOperationKindV1::Receive {
            return Err(Error::Authority);
        }
        let original = prepared
            .payment_original
            .as_deref()
            .ok_or(Error::Authority)?;
        let capsule = &step.frozen.capsule;
        if retained_original(
            &capsule.body().retained_inputs,
            KagemushaWalletRetainedInputRoleV1::Payment,
        )? != original
            || retained_original(
                &capsule.body().retained_inputs,
                KagemushaWalletRetainedInputRoleV1::Credential,
            )? != prepared
                .payer
                .as_ref()
                .ok_or(Error::Authority)?
                .credential_original
            || retained_original(
                &capsule.body().retained_inputs,
                KagemushaWalletRetainedInputRoleV1::CertificateSet,
            )? != prepared
                .payer_certificate_set_original
                .as_deref()
                .ok_or(Error::Authority)?
        {
            return Err(Error::Authority);
        }
        let payer = prepared.payer.as_ref().ok_or(Error::Authority)?;
        let incoming = incoming_original::payment(original)?;
        if incoming.payment_digest != capsule.body().payment_digest {
            return Err(Error::Authority);
        }
        let (after, statement, receipt) =
            self.retained_monetary(owner, step, predecessor, prepared, public, budget)?;
        let quoted = &prepared.request.receiver_credential;
        let quoted_certificate = authority(prepared.request.certificates.certificate(
            &quoted.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        ))?;
        let consumed = *prepared.maps.first().ok_or(Error::Authority)?;
        Ok(ReceiveSourceFieldsV1 {
            before: predecessor.witness,
            after,
            statement,
            // A1 proves this witness's relation; native prepare evaluates it to the
            // exact committed statement first. σ_recv itself is retained for the payer.
            step: prepared.witness.clone(),
            consumed,
            incoming_statement: incoming.incoming_statement,
            objects: [
                signed_tape(
                    authority(incoming.payment.signed_request())?
                        .body
                        .transcript(),
                    &incoming.payment.request.signature,
                ),
                payer.credential_tape.clone(),
                incoming.receipt,
                incoming.compact,
                incoming.omega,
                incoming.payment.send.step_proof.bytes.clone(),
                receipt,
                signed_tape(quoted.body.transcript(), &quoted.signature),
                signed_tape(
                    quoted_certificate.body.transcript(),
                    &quoted_certificate.signature,
                ),
            ],
            credential: owner.credential_tape.clone(),
            predecessor: native_receive::PredecessorInput {
                proof: predecessor.proof.clone(),
                pallas: predecessor.pallas,
                vesta: predecessor.vesta,
            },
        })
    }

    /// Reconstruct all nine Receive tapes before the independent Q proofs exist,
    /// including both original proof carriers, the quoted credential through renewal,
    /// and the step witness whose relation A1 proves inline. The canonical A relation
    /// derives every incoming validity/correction/burn result and fully checks all
    /// permanent routes and Qs. `incoming_witness` only proposes total decoder and
    /// verifier witnesses; fixed source owners constrain every proposal against the
    /// exact original tapes. The borrowed `credit` is the exact preserve-first membership
    /// or insertion against the predecessor credit root.
    ///
    /// # Errors
    /// Changed retained original/source, noncanonical route or failed native source proof.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive_fold_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        prepared: &MonetaryStepV1,
        public: &KagemushaWalletLineagePublicV1,
        credit: &KagemushaWalletCreditDigestRecordV1,
        incoming_witness: native_receive::IncomingWitness,
        budget: MemoryBudget,
    ) -> Result<ReceiveFoldFieldsV1, Error> {
        let source =
            self.receive_source_fields(owner, step, predecessor, prepared, public, budget)?;
        // These are witness proposals only. Each of the four fixed native owners
        // independently derives its result, and the terminal relation enforces their
        // conjunction and the absence of corrected claims. Bind this proposal to both adjusted burn and the first record.
        let corrected = incoming_witness
            .modes
            .contains(&iroha_kagemusha_proof::q_sigma::native::IncomingMode::Corrected);
        let burned = corrected || !incoming_witness.results.iter().all(|result| *result);
        let amount = match prepared.statement.effect {
            KagemushaWalletEffectV1::Receive { amount, .. } => amount,
            _ => return Err(Error::Authority),
        };
        let expected_burn = proposed_receive_burn(
            predecessor.lineage.public.burned_total,
            amount,
            incoming_witness.results,
            corrected,
        )?;
        if public.burned_total != expected_burn {
            return Err(Error::Authority);
        }
        let credit_entry = KagemushaWalletCreditDigestLeafV1 {
            credit_id: prepared.request.credit_id(),
            payment_digest: step.frozen.capsule.body().payment_digest,
            burned,
        };
        let credit = receive_credit_route(
            credit,
            &predecessor.lineage.public.credit_digest_root,
            &public.credit_digest_root,
            &credit_entry,
        )?;
        Ok(ReceiveFoldFieldsV1 {
            transition: native_receive::Transition {
                before: source.before,
                after: source.after,
                statement: source.statement,
                consumed: source.consumed,
                credit,
                // This is the committed consumed-root insertion, not the permanent
                // credit record's preserve-first branch. Honest preparation always inserts.
                insert: true,
            },
            incoming_statement: source.incoming_statement,
            step: source.step,
            objects: source.objects,
            credential: source.credential,
            incoming: incoming_witness,
            predecessor: source.predecessor,
        })
    }
}

fn proposed_receive_burn(
    previous: u128,
    amount: u128,
    results: [bool; 4],
    corrected: bool,
) -> Result<u128, Error> {
    previous
        .checked_add(if !corrected && results.iter().all(|result| *result) {
            0
        } else {
            amount
        })
        .ok_or(Error::Authority)
}

fn receive_credit_route(
    record: &KagemushaWalletCreditDigestRecordV1,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    entry: &KagemushaWalletCreditDigestLeafV1,
) -> Result<IndexedInsert<Fp>, Error> {
    if authority(record.verify(old_root, entry))? != *new_root {
        return Err(Error::Authority);
    }
    match record {
        KagemushaWalletCreditDigestRecordV1::Inserted { witness } => insertion(witness),
        KagemushaWalletCreditDigestRecordV1::Present { leaf, opening } => Ok(IndexedInsert {
            leaf: IndexedLeaf {
                key: word(leaf.key)?,
                value: word(leaf.value)?,
                next_key: word(leaf.next_key)?,
            },
            leaf_slot: opening.slot,
            leaf_siblings: fields(opening.siblings.to_vec())?,
            ..unused_insert()
        }),
    }
}

// Only actual insertions belong to canonical recovery capsule map_openings. The
// separately retained in-memory fee witness is still required even when fee == 0.
pub(super) fn send_insertions(
    pending: &KagemushaWalletIndexedInsertV1,
    fee: u128,
    fee_witness: &IndexedInsert<Fp>,
) -> Result<Vec<IndexedInsert<Fp>>, Error> {
    let mut maps = vec![insertion(pending)?];
    if fee != 0 {
        maps.push(*fee_witness);
    }
    Ok(maps)
}

pub(super) fn send_fee_map(
    root: &[u8; 32],
    fee: KagemushaWalletFeeClaimLeafV1,
    witness: &SendFeeMapV1,
) -> Result<([u8; 32], IndexedInsert<Fp>), Error> {
    match (fee.fee != 0, witness) {
        (true, SendFeeMapV1::Insert(insert)) => {
            let new_root =
                authority(insert.verify(root, &fee.key(), &authority(fee.leaf_value())?))?;
            Ok((new_root, insertion(insert)?))
        }
        (false, SendFeeMapV1::Preserve { leaf, opening }) => {
            if authority(opening.leaf_root(leaf))? != *root {
                return Err(Error::Authority);
            }
            // insert_if authenticates both paths even when its insert bit is zero.
            // They must describe the same existing leaf, including after earlier fees.
            let unchanged = KagemushaWalletIndexedInsertV1 {
                low: *leaf,
                low_opening: *opening,
                slot_opening: *opening,
            };
            Ok((*root, insertion(&unchanged)?))
        }
        _ => Err(Error::Authority),
    }
}

fn unused_insert() -> IndexedInsert<Fp> {
    IndexedInsert {
        leaf: IndexedLeaf {
            key: Fp::from(0),
            value: Fp::from(0),
            next_key: Fp::from(0),
        },
        leaf_slot: 0,
        leaf_siblings: [Fp::from(0); 32],
        slot: 0,
        slot_siblings: [Fp::from(0); 32],
    }
}
