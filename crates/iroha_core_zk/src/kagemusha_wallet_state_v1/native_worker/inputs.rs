//! Source-selected preparation replay and fixed native operation/Q input assembly.

use super::super::{archive as custody_codec, *};
use super::archive as native_archive;
use super::retention::{
    RetainedChainV1, RetainedFoldV1, RetainedQV1, RetainedStageV1, RetentionKeyV1, payload_digest,
};
use super::*;
use crate::kagemusha_wallet_preparation_v1::{
    ArchiveFoldFieldsV1, AuthenticatedCredentialV1, BootstrapFoldFieldsV1, ConsumingFoldFieldsV1,
    LoadFoldFieldsV1, NativeChoicesV1, PreparationV1, PreparedOperationV1, ReceiveFoldFieldsV1,
    RefreshFoldFieldsV1, RefreshOwnersV1, SendFoldFieldsV1,
};
use iroha_kagemusha_proof::{
    a_relation::schedule::compiled::compiled_routes, operation_relation::objects::ObjectKind,
    q_sigma::SigmaSlotWitness, q_signature::SignatureWitness,
};
use iroha_plonk_gadgets::{bytes::p_bytes_native, p256::native::words_from_be};
use iroha_plonk_recursion::obligation::ledger::Variant;

const CREDENTIAL_KEY: usize = 130;
const CERTIFICATE_KEY: usize = 35;

pub(super) fn key(tape: &[u8], offset: usize) -> Result<[[u64; 4]; 2], Error> {
    let bytes = tape
        .get(offset..offset.checked_add(65).ok_or(Error::Proof("key offset"))?)
        .ok_or(Error::Proof("signed object key length"))?;
    // Preserve raw integers. The object relation binds the SEC1 prefix and Q checks
    // curve/canonicality; rejecting an incoming bad point here would bypass soft verification.
    Ok([
        words_from_be(bytes[1..33].try_into().map_err(|_| Error::Proof("key x"))?),
        words_from_be(
            bytes[33..65]
                .try_into()
                .map_err(|_| Error::Proof("key y"))?,
        ),
    ])
}
pub(super) fn signature(
    kind: ObjectKind,
    tape: &[u8],
    key: [[u64; 4]; 2],
) -> Result<SignatureWitness, Error> {
    let body = kind.body_len();
    if tape.len()
        != body
            .checked_add(64)
            .ok_or(Error::Proof("signature length"))?
    {
        return Err(Error::Proof("signed object exact schema"));
    }
    Ok(SignatureWitness {
        digest: p_bytes_native(kind.signing_domain(), &tape[..body]),
        key,
        signature: [
            words_from_be(
                tape[body..body + 32]
                    .try_into()
                    .map_err(|_| Error::Proof("signature r"))?,
            ),
            words_from_be(
                tape[body + 32..]
                    .try_into()
                    .map_err(|_| Error::Proof("signature s"))?,
            ),
        ],
    })
}
fn own_signatures(
    receipt: &[u8],
    credential: &[u8],
    certificate: &[u8],
    root: [[u64; 4]; 2],
) -> Result<Vec<SignatureWitness>, Error> {
    Ok(vec![
        signature(
            ObjectKind::Receipt,
            receipt,
            key(credential, CREDENTIAL_KEY)?,
        )?,
        signature(
            ObjectKind::Credential,
            credential,
            key(certificate, CERTIFICATE_KEY)?,
        )?,
        signature(ObjectKind::Certificate, certificate, root)?,
    ])
}
/// The merged Receive signature leaf: the own receipt under the payment key its
/// current credential opens (hard), then the Send receipt under the payer key and
/// the Request under the quoted receiver key (soft), plus the quoted credential
/// and its certificate under the scheme root when renewed (soft).
pub(super) fn receive_signatures(
    objects: &[Vec<u8>; 9],
    credential: &[u8],
    renewed: bool,
    root: [[u64; 4]; 2],
) -> Result<Vec<SignatureWitness>, Error> {
    let mut witnesses = vec![
        signature(
            ObjectKind::Receipt,
            &objects[6],
            key(credential, CREDENTIAL_KEY)?,
        )?,
        signature(
            ObjectKind::Receipt,
            &objects[2],
            key(&objects[1], CREDENTIAL_KEY)?,
        )?,
        signature(
            ObjectKind::Request,
            &objects[0],
            key(&objects[7], CREDENTIAL_KEY)?,
        )?,
    ];
    if renewed {
        witnesses.extend([
            signature(
                ObjectKind::Credential,
                &objects[7],
                key(&objects[8], CERTIFICATE_KEY)?,
            )?,
            signature(ObjectKind::Certificate, &objects[8], root)?,
        ]);
    }
    Ok(witnesses)
}

fn original(step: &ReleasedStep, role: KagemushaWalletRetainedInputRoleV1) -> Result<&[u8], Error> {
    let mut values = step
        .frozen
        .capsule
        .body()
        .retained_inputs
        .iter()
        .filter(|item| item.role == role);
    let first = values
        .next()
        .ok_or(Error::WitnessLost("native fold original"))?;
    if values.next().is_some() || first.bytes.is_empty() {
        return Err(Error::WitnessLost("ambiguous native fold original"));
    }
    Ok(&first.bytes)
}
fn incoming_send_selector(payment: &KagemushaWalletPaymentV1) -> Result<u8, Error> {
    let controls = payment
        .send
        .lineage
        .lineage()
        .ok_or(Error::Invalid("incoming Send lineage shape"))?
        .public
        .enabled_controls;
    // This is exactly IncomingPaymentCells' total selector. Invalid control words select
    // the fixed Send0 key while Objects records false; statement metadata is not authority.
    let selected = u8::try_from(controls)
        .ok()
        .filter(|value| *value <= 3)
        .unwrap_or(0);
    Ok(2 + selected)
}
fn selector(step: &ReleasedStep) -> Result<OperationRoute, Error> {
    use KagemushaWalletOperationKindV1 as K;
    use KagemushaWalletRetainedInputRoleV1 as R;
    let capsule = &step.frozen.capsule;
    let (variant, own, incoming) = match capsule.body().kind {
        K::Bootstrap => (Variant::Bootstrap, 0, None),
        K::Load => (Variant::Load, 1, None),
        K::Send => (
            Variant::Send,
            2_u8.checked_add(
                u8::try_from(capsule.body().statement.enabled_controls)
                    .map_err(|_| Error::Invalid("Send mask"))?,
            )
            .ok_or(Error::Invalid("Send mask"))?,
            None,
        ),
        K::Receive => {
            let request: KagemushaWalletRequestV1 =
                custody_codec::decode(original(step, R::Request)?)?;
            let payment: KagemushaWalletPaymentV1 =
                custody_codec::decode(original(step, R::Payment)?)?;
            let variant = if request.receiver_credential.credential_digest()
                == step.frozen.credential.credential_digest()
            {
                Variant::Receive
            } else {
                Variant::ReceiveRenewed
            };
            (variant, 6, Some(incoming_send_selector(&payment)?))
        }
        K::ArchiveSent => {
            let evidence: KagemushaWalletCreditedV1 =
                custody_codec::decode(original(step, R::Credited)?)?;
            match evidence.evidence {
                KagemushaWalletCreditedEvidenceV1::Receive { .. } => {
                    (Variant::ArchiveReceive, 7, Some(6))
                }
                KagemushaWalletCreditedEvidenceV1::Status { .. } => {
                    (Variant::ArchiveStatus, 7, None)
                }
            }
        }
        K::Unload => (Variant::Unload, 8, None),
        K::RefreshPolicy => {
            let KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } =
                capsule.body().statement.effect
            else {
                return Err(Error::Invalid("Refresh route"));
            };
            let variant = match update_kind {
                KagemushaWalletPolicyUpdateKindV1::Credential => Variant::RefreshCredential,
                KagemushaWalletPolicyUpdateKindV1::SchemePolicy => Variant::RefreshSchemePolicy,
                KagemushaWalletPolicyUpdateKindV1::QuotaShare => Variant::RefreshQuotaShare,
                KagemushaWalletPolicyUpdateKindV1::TimeAnchor => Variant::RefreshTimeAnchor,
            };
            (variant, 9, None)
        }
        K::Retiring => (Variant::Retiring, 10, None),
    };
    let route = OperationRoute {
        variant,
        own,
        incoming,
    };
    if !compiled_routes().contains(&route) {
        return Err(Error::Invalid("uncompiled native operation route"));
    }
    Ok(route)
}

#[allow(
    clippy::large_enum_variant,
    reason = "one active bounded operation is moved into native prepare"
)]
pub(super) enum Fields {
    Bootstrap(BootstrapFoldFieldsV1),
    Load(LoadFoldFieldsV1),
    Send(SendFoldFieldsV1),
    Receive(ReceiveFoldFieldsV1),
    Archive(ArchiveFoldFieldsV1),
    Consuming(ConsumingFoldFieldsV1),
    Refresh(RefreshFoldFieldsV1),
}
impl Fields {
    fn signatures(
        &self,
        root: [[u64; 4]; 2],
        variant: Variant,
    ) -> Result<Vec<Vec<SignatureWitness>>, Error> {
        Ok(match self {
            Self::Bootstrap(f) => vec![own_signatures(
                &f.objects[2],
                &f.objects[1],
                &f.objects[0],
                root,
            )?],
            // Lean lineage: the own receipt is Load's only signature leaf.
            Self::Load(f) => vec![vec![signature(
                ObjectKind::Receipt,
                &f.objects[0],
                key(&f.credential, CREDENTIAL_KEY)?,
            )?]],
            // Lean lineage: the own receipt is Send's only signature leaf, under the
            // payment key its current credential opens.
            Self::Send(f) => vec![vec![signature(
                ObjectKind::Receipt,
                &f.objects[3],
                key(&f.objects[0], CREDENTIAL_KEY)?,
            )?]],
            // Lean lineage: one merged leaf, the own receipt first.
            Self::Receive(f) => vec![receive_signatures(
                &f.objects,
                &f.credential,
                variant == Variant::ReceiveRenewed,
                root,
            )?],
            // Lean lineage: one merged leaf, the own receipt hard under the payment
            // key its current credential opens, then the incoming receipt soft under
            // the Request's quoted receiver key.
            Self::Archive(f) => {
                let receipt = match &f.evidence {
                    native_archive::Evidence::Receive { receipt, .. }
                    | native_archive::Evidence::Status { receipt, .. } => receipt,
                };
                vec![vec![
                    signature(
                        ObjectKind::Receipt,
                        &f.own,
                        key(&f.credential, CREDENTIAL_KEY)?,
                    )?,
                    signature(
                        ObjectKind::Receipt,
                        receipt,
                        key(&f.retained.signed[3], CREDENTIAL_KEY)?,
                    )?,
                ]]
            }
            // Lean lineage: the own receipt is Unload's and Retiring's only signature leaf.
            Self::Consuming(f) => vec![vec![signature(
                ObjectKind::Receipt,
                &f.objects[0],
                key(&f.credential, CREDENTIAL_KEY)?,
            )?]],
            Self::Refresh(f) => {
                let kind = match variant {
                    Variant::RefreshCredential => ObjectKind::Credential,
                    Variant::RefreshSchemePolicy => ObjectKind::SchemePolicy,
                    Variant::RefreshQuotaShare => ObjectKind::QuotaShare,
                    Variant::RefreshTimeAnchor => ObjectKind::TimeAnchor,
                    _ => return Err(Error::Proof("Refresh signature route")),
                };
                vec![
                    vec![
                        signature(
                            ObjectKind::Receipt,
                            &f.objects[2],
                            key(&f.objects[4], CREDENTIAL_KEY)?,
                        )?,
                        signature(kind, &f.objects[1], key(&f.objects[0], CERTIFICATE_KEY)?)?,
                        signature(ObjectKind::Certificate, &f.objects[0], root)?,
                    ],
                    vec![
                        signature(
                            ObjectKind::Credential,
                            &f.objects[4],
                            key(&f.objects[3], CERTIFICATE_KEY)?,
                        )?,
                        signature(ObjectKind::Certificate, &f.objects[3], root)?,
                    ],
                ]
            }
        })
    }
    fn with_q(self, originals: Vec<q_checkpoint::Original>) -> Result<OperationInputsV1, Error> {
        macro_rules! attach {
            ($fields:expr,$module:ident,$count:literal,$variant:ident) => {{
                let q: [$module::QInput; $count] = originals
                    .into_iter()
                    .map(|q| $module::QInput {
                        proof: q.proof,
                        instances: q.instances,
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| Error::Proof("native Q arity"))?;
                OperationInputsV1::$variant($fields.with_q(q))
            }};
        }
        Ok(match self {
            Self::Bootstrap(f) => attach!(f, bootstrap, 1, Bootstrap),
            Self::Load(f) => attach!(f, load, 1, Load),
            Self::Send(f) => attach!(f, send, 1, Send),
            Self::Receive(f) => attach!(f, receive, 2, Receive),
            // Archive's Q arity follows its evidence variant (two or one); the
            // installed native plan rejects any other count.
            Self::Archive(f) => OperationInputsV1::Archive(
                f.with_q(
                    originals
                        .into_iter()
                        .map(|q| native_archive::QInput {
                            proof: q.proof,
                            instances: q.instances,
                        })
                        .collect(),
                ),
            ),
            Self::Consuming(f) => attach!(f, consuming, 1, Consuming),
            Self::Refresh(f) => attach!(f, refresh, 3, Refresh),
        })
    }
}

impl NativeFoldWorkerV1 {
    fn owner(
        &self,
        preparation: &PreparationV1<'_>,
        custody: &mut FoldCustodyV1<'_>,
        predecessor: bool,
    ) -> Result<AuthenticatedCredentialV1, Error> {
        let mut read = |role| {
            if predecessor {
                custody.predecessor_original(role)
            } else {
                custody.successor_original(role)
            }
        };
        let credential = read(PreparationOriginalV1::CurrentCredential)?
            .ok_or(Error::WitnessLost("fold own credential"))?;
        let certificates = read(PreparationOriginalV1::EnrollmentCertificates)?
            .ok_or(Error::WitnessLost("fold own issuer set"))?;
        preparation.authenticate_credential_set(&credential, &certificates)
    }
    fn replay(
        &self,
        preparation: &PreparationV1<'_>,
        step: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        custody: &mut FoldCustodyV1<'_>,
    ) -> Result<PreparedOperationV1, Error> {
        let before = custody
            .predecessor()
            .ok_or(Error::WitnessLost("native fold source"))?
            .clone();
        let source = PreparationSourceV1 {
            released: &before,
            folded: predecessor,
        };
        let (intent, plan, draft, mut selected) = custody.preparation()?;
        let choices = NativeChoicesV1::decode(
            plan,
            self.installed.verifier().manifest_digest(),
            intent,
            &source,
        )?;
        let prepared = preparation.restore_operation(
            intent,
            &step.frozen,
            &source,
            &mut selected,
            &self.sources,
            choices.nonce(),
            choices.time().as_ref(),
            self.budget,
        )?;
        prepared.verify_frozen(preparation, &step.frozen, self.budget)?;
        let actual = selected.finish(&step.frozen.capsule.body().successor_state)?;
        if custody_codec::encode(&actual)? != custody_codec::encode(draft)? {
            return Err(Error::WitnessLost("fold changed native preparation"));
        }
        Ok(prepared)
    }
    pub(crate) fn schedule(
        &self,
        step: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        custody: &mut FoldCustodyV1<'_>,
    ) -> Result<Vec<CheckpointLayout>, Error> {
        if (step.frozen.capsule.body().kind == KagemushaWalletOperationKindV1::Bootstrap)
            != predecessor.is_none()
            || custody.predecessor().is_some() != predecessor.is_some()
        {
            return Err(Error::WitnessLost("fold schedule predecessor"));
        }
        self.route_schedule(selector(step)?)
    }
    /// Revalidate the proving originals of the sub-proof that `checkpoints` selects: the next
    /// Q, the next A or W, or the final Ω of a schedule of `stages` with `q_count` Q stages.
    /// The prepared job binds the same already-admitted source without the original store.
    fn revalidate(
        &self,
        route: OperationRoute,
        checkpoints: usize,
        q_count: usize,
        stages: usize,
        originals: &mut dyn OriginalSourceV1,
        cancellation: &Cancellation,
    ) -> Result<(), Error> {
        fold_metrics::enter(FoldPhaseV1::KeyImport);
        let token = Some(cancellation.prover_token());
        if checkpoints < q_count {
            fold_metrics::stage(FoldStageV1::Q);
            self.sources
                .import_q_cancellable(route, checkpoints, originals, self.read, token)
                .map_err(artifact)?;
        } else if checkpoints < stages {
            let position = checkpoints - q_count;
            if position % 2 == 1 {
                fold_metrics::stage(FoldStageV1::W);
                self.sources
                    .import_w_cancellable(route, position / 2, originals, self.read, token)
                    .map_err(artifact)?;
            } else {
                fold_metrics::stage(FoldStageV1::A);
                self.sources
                    .import_a_cancellable(route, position / 2, originals, self.read, token)
                    .map_err(artifact)?;
            }
        } else {
            fold_metrics::stage(FoldStageV1::Omega);
            self.sources
                .import_omega_cancellable(originals, self.read, token)
                .map_err(artifact)?;
        }
        cancellation.check()
    }
    /// Under the wallet owner: replay the step's preparation from `custody`, assemble its
    /// native inputs and revalidate the proving originals of the selected stage. The returned
    /// job owns them with a copy of this worker and proves without the owner; no custody,
    /// archive or original-store handle crosses into it.
    ///
    /// When `retained` belongs to this sub-proof's durable inputs and its restored payloads are
    /// a byte-exact prefix of `checkpoints`, the step's derived inputs are resumed instead of
    /// replayed (D6b): owner authentication, the folded predecessor state, the preparation
    /// replay and the fold-field derivation are skipped. Anything else runs today's derivation
    /// in this call. The schedule, the key imports and every native check always run.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare(
        &self,
        step: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        checkpoints: Vec<PrivateArchiveBytes>,
        retained: Option<FoldRetentionV1>,
        cancellation: &Cancellation,
        originals: &mut dyn OriginalSourceV1,
        custody: &mut FoldCustodyV1<'_>,
    ) -> Result<Box<dyn NativeFoldJobV1>, Error> {
        cancellation.check()?;
        fold_metrics::enter(FoldPhaseV1::OwnerReplay);
        let route = selector(step)?;
        let schedule = self.schedule(step, predecessor, custody)?;
        if checkpoints.len() > schedule.len() {
            return Err(Error::Proof("native checkpoint count"));
        }
        let q_count = proof(self.sources.q(route))?.keys().len();
        // This sub-proof's durable inputs, read before any derivation touches `custody`, and the
        // identity of every durable payload the coordinator re-chained in this turn.
        let key = RetentionKeyV1::new(self, route, step, predecessor, custody)?;
        let durable: Vec<[u8; 32]> = checkpoints.iter().map(payload_digest).collect();
        let warm = retained.and_then(|retained| self.admit(retained, &key, &durable, q_count));
        let (public, stage) = match warm {
            Some(warm) => {
                self.resume_inputs(warm, step, checkpoints.len(), q_count, cancellation)?
            }
            None => self.derive_inputs(
                step,
                predecessor,
                route,
                checkpoints.len(),
                q_count,
                custody,
                cancellation,
            )?,
        };
        self.revalidate(
            route,
            checkpoints.len(),
            q_count,
            schedule.len(),
            originals,
            cancellation,
        )?;
        Ok(Box::new(NativeStageJobV1 {
            worker: self.clone(),
            route,
            source: step.frozen.capsule.custody_digest(),
            key,
            durable,
            checkpoints,
            q_count,
            public,
            predecessor_burned: predecessor.map(|record| record.lineage.public.burned_total),
            stage,
        }))
    }

    /// The warm path: the derived inputs the previous sub-proof of this step left. The first
    /// A/W sub-proof computes the lineage fields from the retained owner, as the cold path
    /// computes them from the same owner and public fields.
    fn resume_inputs(
        &self,
        warm: RetainedFoldV1,
        step: &ReleasedStep,
        checkpoints: usize,
        q_count: usize,
        cancellation: &Cancellation,
    ) -> Result<(KagemushaWalletLineagePublicV1, JobStageV1), Error> {
        #[cfg(test)]
        super::retention::count(|counts| counts.warm += 1);
        let RetainedFoldV1 {
            held,
            public,
            stage,
            ..
        } = warm;
        let stage = match stage {
            RetainedStageV1::Q(retained) => {
                let RetainedQV1 {
                    owner,
                    fields,
                    q_sources,
                    q,
                } = *retained;
                if checkpoints < q_count {
                    JobStageV1::Q(Box::new(QJobV1 {
                        owner,
                        fields,
                        q_sources,
                        q,
                    }))
                } else {
                    let preparation = proof(PreparationV1::new(&self.installed))?
                        .with_cancellation(cancellation.prover_token());
                    let successor = &step.frozen.capsule.body().successor_state;
                    let public_fields =
                        proof(preparation.state_fields(&owner, successor, &public))?.lineage;
                    JobStageV1::Prepare(Box::new(PrepareJobV1 {
                        fields,
                        q_sources,
                        public_fields,
                        q,
                    }))
                }
            }
            // Admitted with every Q payload restored, so `held` covers the whole Q prefix.
            RetainedStageV1::Chain(chain) => {
                JobStageV1::Resume(chain, held.len().saturating_sub(q_count))
            }
        };
        Ok((public, stage))
    }

    /// The cold path, today's derivation from custody: owner authentication, the folded
    /// predecessor state, the preparation replay, and the fold fields and Q sources of the
    /// route, with the lineage fields once every Q source exists.
    #[allow(clippy::too_many_arguments)]
    fn derive_inputs(
        &self,
        step: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        route: OperationRoute,
        checkpoints: usize,
        q_count: usize,
        custody: &mut FoldCustodyV1<'_>,
        cancellation: &Cancellation,
    ) -> Result<(KagemushaWalletLineagePublicV1, JobStageV1), Error> {
        #[cfg(test)]
        super::retention::count(|counts| counts.derivations += 1);
        let preparation = proof(PreparationV1::new(&self.installed))?
            .with_cancellation(cancellation.prover_token());
        let owner = self.owner(&preparation, custody, false)?;
        let current = if predecessor.is_some() {
            Some(self.owner(&preparation, custody, true)?)
        } else {
            None
        };
        let folded = if let Some(record) = predecessor {
            Some(proof(preparation.folded_state(
                current.as_ref().ok_or(Error::NoHead)?,
                custody.predecessor().ok_or(Error::NoHead)?,
                record,
                self.budget,
            ))?)
        } else {
            None
        };
        let prepared = if route.variant == Variant::Bootstrap {
            None
        } else {
            Some(self.replay(&preparation, step, predecessor, custody)?)
        };
        cancellation.check()?;
        let state = &step.frozen.capsule.body().successor_state;
        let mut public = KagemushaWalletLineagePublicV1 {
            version: 1,
            scheme_id: state.core.scheme_id,
            relation_id: self.installed.verifier().scheme().relation_id,
            head: valid(state.commitment())?,
            wallet_id: state.core.wallet_id,
            credential_digest: state.core.credential_digest,
            payment_key: owner.credential().body.payment_key,
            lifecycle: state.core.lifecycle,
            policy_epoch: state.core.policy_epoch,
            enabled_controls: state.core.enabled_controls,
            burned_total: predecessor.map_or(0, |record| record.lineage.public.burned_total),
            pending_outgoing_root: custody.pending_root(),
            credit_digest_root: custody.credit_root(),
        };
        let mut incoming = None;
        let fields = match route.variant {
            Variant::Bootstrap => Fields::Bootstrap(proof(preparation.bootstrap_fold_fields(
                &owner,
                step,
                &public,
                self.budget,
            ))?),
            Variant::Load => {
                let QualifiedOperationOwnerV1::Load(_) = proof(self.sources.route(route))?.owner()
                else {
                    return Err(Error::Proof("Load owner"));
                };
                Fields::Load(preparation.load_fold_fields(
                    &owner,
                    step,
                    folded.as_ref().ok_or(Error::FoldRequired)?,
                    &public,
                    self.budget,
                )?)
            }
            Variant::Send => {
                custody.pending_insert()?;
                public.pending_outgoing_root = custody.pending_root();
                Fields::Send(proof(
                    preparation.send_fold_fields(
                        &owner,
                        step,
                        folded.as_ref().ok_or(Error::FoldRequired)?,
                        prepared
                            .as_ref()
                            .and_then(PreparedOperationV1::monetary)
                            .ok_or(Error::Proof("Send preparation"))?,
                        &public,
                        self.budget,
                    ),
                )?)
            }
            Variant::Receive | Variant::ReceiveRenewed => {
                let (fields, proposal) = super::incoming_inputs::receive(
                    self,
                    &preparation,
                    prepared
                        .as_ref()
                        .ok_or(Error::Proof("Receive preparation"))?,
                    step,
                    folded.as_ref().ok_or(Error::FoldRequired)?,
                    &mut public,
                    custody,
                    route,
                    cancellation,
                )?;
                incoming = proposal;
                Fields::Receive(fields)
            }
            Variant::ArchiveReceive | Variant::ArchiveStatus => {
                let (fields, proposal) = super::incoming_inputs::archive(
                    self,
                    &preparation,
                    prepared
                        .as_ref()
                        .ok_or(Error::Proof("Archive preparation"))?,
                    step,
                    folded.as_ref().ok_or(Error::FoldRequired)?,
                    &mut public,
                    custody,
                    route,
                    cancellation,
                )?;
                incoming = proposal;
                Fields::Archive(fields)
            }
            Variant::Unload | Variant::Retiring => {
                Fields::Consuming(proof(preparation.consuming_fold_fields(
                    &owner,
                    step,
                    folded.as_ref().ok_or(Error::FoldRequired)?,
                    &public,
                    self.budget,
                ))?)
            }
            _ => {
                let KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } =
                    step.frozen.capsule.body().statement.effect
                else {
                    return Err(Error::Proof("Refresh update kind"));
                };
                let role = match update_kind {
                    KagemushaWalletPolicyUpdateKindV1::Credential => {
                        PreparationOriginalV1::CurrentCredential
                    }
                    KagemushaWalletPolicyUpdateKindV1::SchemePolicy => {
                        PreparationOriginalV1::SchemePolicy
                    }
                    KagemushaWalletPolicyUpdateKindV1::QuotaShare => {
                        PreparationOriginalV1::QuotaShare
                    }
                    KagemushaWalletPolicyUpdateKindV1::TimeAnchor => {
                        PreparationOriginalV1::TimeAnchor
                    }
                };
                let original = custody
                    .successor_original(role)?
                    .ok_or(Error::WitnessLost("Refresh successor original"))?;
                Fields::Refresh(proof(preparation.refresh_fold_fields(
                    RefreshOwnersV1 {
                        current: current.as_ref().ok_or(Error::NoHead)?,
                        successor: &owner,
                    },
                    step,
                    folded.as_ref().ok_or(Error::FoldRequired)?,
                    &public,
                    &original,
                    self.budget,
                ))?)
            }
        };
        let root = self.sources.scope().root();
        let sigma = &step.frozen.capsule.body().step_proof.bytes;
        // A lean route's A proves the own step directly: no own sigma witness.
        let own =
            if iroha_kagemusha_proof::a_relation::schedule::proves_own_step_inline(route.variant) {
                None
            } else {
                let own_key = self
                    .sources
                    .sigmas()
                    .key(route.own)
                    .ok_or(Error::Proof("own sigma selector"))?;
                Some(SigmaSlotWitness {
                    key: own_key.key().clone(),
                    statement: Option::<Fp>::from(Fp::from_repr(valid(
                        step.frozen.capsule.body().statement.statement_digest(),
                    )?))
                    .ok_or(Error::Invalid("statement field"))?,
                    proof: sigma.clone(),
                    length: u32::try_from(sigma.len())
                        .map_err(|_| Error::Invalid("sigma length"))?,
                })
            };
        let q_sources = q::QSourcesV1 {
            own,
            incoming,
            signatures: fields.signatures([root.x, root.y], route.variant)?,
        };
        // The A/W stages use the lineage fields only once every Q source exists.
        let job = if checkpoints < q_count {
            JobStageV1::Q(Box::new(QJobV1 {
                owner,
                fields,
                q_sources,
                q: None,
            }))
        } else {
            let public_fields = proof(preparation.state_fields(&owner, state, &public))?.lineage;
            JobStageV1::Prepare(Box::new(PrepareJobV1 {
                fields,
                q_sources,
                public_fields,
                q: None,
            }))
        };
        Ok((public, job))
    }
}

/// One prepared native sub-proof: owned inputs and a copy of the metadata-only worker, with
/// no custody, archive or original-store handle.
struct NativeStageJobV1 {
    worker: NativeFoldWorkerV1,
    route: OperationRoute,
    // Custody digest of the selected capsule, the private Q checkpoint identity.
    source: [u8; 32],
    // This sub-proof's durable inputs and the identity of every durable payload, for the state
    // it may leave to the next sub-proof of the step.
    key: RetentionKeyV1,
    durable: Vec<[u8; 32]>,
    checkpoints: Vec<PrivateArchiveBytes>,
    q_count: usize,
    public: KagemushaWalletLineagePublicV1,
    predecessor_burned: Option<u128>,
    stage: JobStageV1,
}

/// Where one prepared sub-proof starts.
enum JobStageV1 {
    /// Before every Q source exists: the next Q proof.
    Q(Box<QJobV1>),
    /// Every Q source exists and no family session is retained: restore the Q chain and
    /// prepare the family session from the step's complete inputs.
    Prepare(Box<PrepareJobV1>),
    /// The family session the previous sub-proof retained, and how many A/W checkpoints it
    /// already restored.
    Resume(Box<RetainedChainV1>, usize),
}

struct QJobV1 {
    owner: AuthenticatedCredentialV1,
    fields: Fields,
    q_sources: q::QSourcesV1,
    q: Option<Box<q::QStateV1>>,
}

struct PrepareJobV1 {
    fields: Fields,
    q_sources: q::QSourcesV1,
    public_fields: [Fp; 18],
    q: Option<Box<q::QStateV1>>,
}

impl NativeFoldJobV1 for NativeStageJobV1 {
    fn prove(
        self: Box<Self>,
        cancellation: &Cancellation,
    ) -> Result<(FoldProgress, Option<FoldRetentionV1>), Error> {
        let Self {
            worker,
            route,
            source,
            key,
            durable,
            checkpoints,
            q_count,
            public,
            predecessor_burned,
            stage,
        } = *self;
        let q_checkpoints = &checkpoints[..checkpoints.len().min(q_count)];
        let (session, public_fields, restored) = match stage {
            JobStageV1::Q(job) => {
                let QJobV1 {
                    owner,
                    fields,
                    q_sources,
                    q,
                } = *job;
                return match worker.q_stage(
                    route,
                    source,
                    &q_sources,
                    q_checkpoints,
                    q,
                    cancellation,
                )? {
                    q::QProgressV1::Checkpoint(bytes, q) => {
                        // Every durable Q payload was restored into `q`, unless σ came from
                        // fresh coins and nothing durable exists yet.
                        let held = if q.is_some() { durable } else { Vec::new() };
                        let retained = RetainedFoldV1 {
                            key,
                            held,
                            public,
                            stage: RetainedStageV1::Q(Box::new(RetainedQV1 {
                                owner,
                                fields,
                                q_sources,
                                q,
                            })),
                        };
                        Ok((
                            FoldProgress::Checkpoint(bytes),
                            Some(FoldRetentionV1::new(retained)),
                        ))
                    }
                    q::QProgressV1::Complete(_) => Err(Error::Proof("native fold lineage fields")),
                };
            }
            JobStageV1::Prepare(job) => {
                let PrepareJobV1 {
                    fields,
                    q_sources,
                    public_fields,
                    q,
                } = *job;
                let q = match worker.q_stage(
                    route,
                    source,
                    &q_sources,
                    q_checkpoints,
                    q,
                    cancellation,
                )? {
                    q::QProgressV1::Checkpoint(bytes, _) => {
                        return Ok((FoldProgress::Checkpoint(bytes), None));
                    }
                    q::QProgressV1::Complete(q) => q,
                };
                (
                    stages::SessionSourceV1::Prepare(Box::new(fields.with_q(q)?)),
                    public_fields,
                    0,
                )
            }
            JobStageV1::Resume(chain, restored) => {
                let RetainedChainV1 {
                    public_fields,
                    family,
                } = *chain;
                (
                    stages::SessionSourceV1::Resume(family),
                    public_fields,
                    restored,
                )
            }
        };
        match worker.stage(
            route,
            session,
            &public_fields,
            &checkpoints[q_count..],
            restored,
            cancellation,
        )? {
            (NativeStageProgressV1::Checkpoint(bytes), family) => {
                // Every durable payload was restored into the session by now.
                let retained = family.map(|family| {
                    FoldRetentionV1::new(RetainedFoldV1 {
                        key,
                        held: durable,
                        public,
                        stage: RetainedStageV1::Chain(Box::new(RetainedChainV1 {
                            public_fields,
                            family,
                        })),
                    })
                });
                Ok((FoldProgress::Checkpoint(bytes), retained))
            }
            (NativeStageProgressV1::Terminal(input), _) => {
                let proof_bytes = worker.finish(input, cancellation)?;
                // A candidate: the coordinator verifies this exact lineage in full before
                // any credit, pending-map, archive or manifest effect.
                let lineage = KagemushaWalletLineageV1 {
                    public,
                    proof: proof_bytes,
                };
                let burned =
                    route.variant == Variant::Receive || route.variant == Variant::ReceiveRenewed;
                let burned = burned
                    && public.burned_total != predecessor_burned.ok_or(Error::FoldRequired)?;
                Ok((FoldProgress::Complete { lineage, burned }, None))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_send_selector_uses_carried_omega_and_total_invalid_mask() {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        let row = vectors["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"].as_str() == Some("KagemushaWalletPaymentV1"))
            .unwrap();
        let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
        let mut payment: KagemushaWalletPaymentV1 = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap();
        for statement_controls in [0, 7, 8, u32::MAX] {
            payment.send.statement.enabled_controls = statement_controls;
            for carried_controls in [0, 1, 2, 3, 4, 5, 6, 7, 255, 256, u32::MAX] {
                let KagemushaWalletLineageSlotV1::Present { lineage } = &mut payment.send.lineage
                else {
                    panic!("fixture lineage");
                };
                lineage.public.enabled_controls = carried_controls;
                assert_eq!(
                    incoming_send_selector(&payment).unwrap(),
                    2 + if carried_controls <= 3 {
                        carried_controls as u8
                    } else {
                        0
                    }
                );
            }
        }
        payment.send.lineage = KagemushaWalletLineageSlotV1::None;
        assert!(incoming_send_selector(&payment).is_err());
    }

    #[test]
    fn raw_signature_projection_preserves_integer_endianness_and_exact_schema() {
        let root = iroha_plonk_gadgets::p256::native::Affine::GENERATOR;
        for kind in ObjectKind::ALL {
            let mut tape = vec![17; kind.body_len() + 64];
            for (index, byte) in tape[kind.body_len()..].iter_mut().enumerate() {
                *byte = u8::try_from(index + 128).unwrap();
            }
            let projected = signature(kind, &tape, [root.x, root.y]).unwrap();
            assert_eq!(projected.key, [root.x, root.y]);
            assert_eq!(
                projected.digest,
                p_bytes_native(kind.signing_domain(), &tape[..kind.body_len()])
            );
            assert_eq!(
                projected.signature[0][0],
                u64::from_be_bytes(
                    tape[kind.body_len() + 24..kind.body_len() + 32]
                        .try_into()
                        .unwrap()
                )
            );
            assert_eq!(
                projected.signature[1][3],
                u64::from_be_bytes(
                    tape[kind.body_len() + 32..kind.body_len() + 40]
                        .try_into()
                        .unwrap()
                )
            );
            let mut changed = tape.clone();
            changed[0] ^= 1;
            assert_ne!(
                signature(kind, &changed, [root.x, root.y]).unwrap().digest,
                projected.digest
            );
            assert!(signature(kind, &tape[..tape.len() - 1], [root.x, root.y]).is_err());
            tape.push(0);
            assert!(signature(kind, &tape, [root.x, root.y]).is_err());
        }
    }

    #[test]
    fn raw_key_projection_does_not_reduce_invalid_incoming_points() {
        let mut tape = vec![0; CREDENTIAL_KEY + 65];
        tape[CREDENTIAL_KEY..].fill(255);
        assert_eq!(key(&tape, CREDENTIAL_KEY).unwrap(), [[u64::MAX; 4]; 2]);
        // Prefix validity belongs to the original object predicate, not this raw-Q adapter.
        tape[CREDENTIAL_KEY] = 4;
        assert_eq!(key(&tape, CREDENTIAL_KEY).unwrap(), [[u64::MAX; 4]; 2]);
        assert!(key(&tape[..tape.len() - 1], CREDENTIAL_KEY).is_err());
        assert!(key(&tape, usize::MAX).is_err());
    }

    #[test]
    fn renewed_receive_signature_slots_bind_quoted_key_and_root_in_native_order() {
        let mut objects: [Vec<u8>; 9] = std::array::from_fn(|_| Vec::new());
        for (index, kind) in [
            (0, ObjectKind::Request),
            (1, ObjectKind::Credential),
            (2, ObjectKind::Receipt),
            (6, ObjectKind::Receipt),
            (7, ObjectKind::Credential),
            (8, ObjectKind::Certificate),
        ] {
            objects[index] = vec![u8::try_from(index + 1).unwrap(); kind.body_len() + 64];
        }
        // The current receiver key is separate from the incoming payer and quoted keys.
        let credential = vec![12; ObjectKind::Credential.body_len() + 64];
        let root = [[7; 4]; 2];
        let normal = receive_signatures(&objects, &credential, false, root).unwrap();
        let renewed = receive_signatures(&objects, &credential, true, root).unwrap();
        assert_eq!(normal.len(), 3);
        assert_eq!(renewed.len(), 5);
        assert_eq!(renewed[0].key, key(&credential, CREDENTIAL_KEY).unwrap());
        assert_eq!(renewed[1].key, key(&objects[1], CREDENTIAL_KEY).unwrap());
        assert_eq!(renewed[2].key, key(&objects[7], CREDENTIAL_KEY).unwrap());
        assert_eq!(renewed[3].key, key(&objects[8], CERTIFICATE_KEY).unwrap());
        assert_eq!(renewed[4].key, root);
        assert_eq!(normal[0].digest, renewed[0].digest);
        assert_eq!(normal[1].digest, renewed[1].digest);
        assert_eq!(normal[2].digest, renewed[2].digest);
        objects[7].push(0);
        assert!(receive_signatures(&objects, &credential, true, root).is_err());
    }
}
