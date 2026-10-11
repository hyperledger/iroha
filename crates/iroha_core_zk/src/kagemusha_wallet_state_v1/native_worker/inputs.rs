//! Source-selected preparation replay and fixed native operation/Q input assembly.

use super::super::{archive as custody_codec, *};
use super::archive as native_archive;
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
pub(super) fn receive_signatures(
    objects: &[Vec<u8>; 11],
    renewed: bool,
    root: [[u64; 4]; 2],
) -> Result<Vec<SignatureWitness>, Error> {
    let mut witnesses = vec![
        signature(
            ObjectKind::Receipt,
            &objects[2],
            key(&objects[1], CREDENTIAL_KEY)?,
        )?,
        signature(
            ObjectKind::Request,
            &objects[0],
            key(&objects[9], CREDENTIAL_KEY)?,
        )?,
    ];
    if renewed {
        witnesses.extend([
            signature(
                ObjectKind::Credential,
                &objects[9],
                key(&objects[10], CERTIFICATE_KEY)?,
            )?,
            signature(ObjectKind::Certificate, &objects[10], root)?,
        ]);
    }
    Ok(witnesses)
}

fn original(step: &ReleasedStep, role: KagemushaWalletRetainedInputRoleV1) -> Result<&[u8], Error> {
    let mut values = step
        .frozen
        .capsule
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
    Ok(2 + if controls <= 7 { controls as u8 } else { 0 })
}
fn selector(step: &ReleasedStep) -> Result<OperationRoute, Error> {
    use KagemushaWalletOperationKindV1 as K;
    use KagemushaWalletRetainedInputRoleV1 as R;
    let capsule = &step.frozen.capsule;
    let (variant, own, incoming) = match capsule.kind {
        K::Bootstrap => (Variant::Bootstrap, 0, None),
        K::Load => (Variant::Load, 1, None),
        K::Send => (
            Variant::Send,
            2_u8.checked_add(
                u8::try_from(capsule.statement.enabled_controls)
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
            (
                variant,
                10 + u8::from(request.body.receiver_blacklist_version != 0),
                Some(incoming_send_selector(&payment)?),
            )
        }
        K::ArchiveSent => {
            let evidence: KagemushaWalletCreditedV1 =
                custody_codec::decode(original(step, R::Credited)?)?;
            let request: KagemushaWalletRequestV1 =
                custody_codec::decode(original(step, R::Request)?)?;
            match evidence.evidence {
                KagemushaWalletCreditedEvidenceV1::Receive { .. } => (
                    Variant::ArchiveReceive,
                    12,
                    Some(10 + u8::from(request.body.receiver_blacklist_version != 0)),
                ),
                KagemushaWalletCreditedEvidenceV1::Status { .. } => {
                    (Variant::ArchiveStatus, 12, None)
                }
            }
        }
        K::Unload => (Variant::Unload, 13, None),
        K::RefreshPolicy => {
            let KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } =
                capsule.statement.effect
            else {
                return Err(Error::Invalid("Refresh route"));
            };
            let variant = match update_kind {
                KagemushaWalletPolicyUpdateKindV1::Credential => Variant::RefreshCredential,
                KagemushaWalletPolicyUpdateKindV1::SchemePolicy => Variant::RefreshSchemePolicy,
                KagemushaWalletPolicyUpdateKindV1::Blacklist => Variant::RefreshBlacklist,
                KagemushaWalletPolicyUpdateKindV1::QuotaShare => Variant::RefreshQuotaShare,
                KagemushaWalletPolicyUpdateKindV1::TimeAnchor => Variant::RefreshTimeAnchor,
            };
            (variant, 14, None)
        }
        K::Retiring => (Variant::Retiring, 15, None),
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
enum Fields {
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
            Self::Load(f) => vec![
                vec![signature(
                    ObjectKind::Receipt,
                    &f.objects[0],
                    key(&f.objects[2], CREDENTIAL_KEY)?,
                )?],
                vec![
                    signature(
                        ObjectKind::Credential,
                        &f.objects[2],
                        key(&f.objects[1], CERTIFICATE_KEY)?,
                    )?,
                    signature(ObjectKind::Certificate, &f.objects[1], root)?,
                ],
            ],
            Self::Send(f) => vec![own_signatures(
                &f.objects[4],
                &f.objects[0],
                &f.objects[3],
                root,
            )?],
            Self::Receive(f) => vec![
                own_signatures(&f.objects[8], &f.objects[6], &f.objects[7], root)?,
                receive_signatures(&f.objects, variant == Variant::ReceiveRenewed, root)?,
            ],
            Self::Archive(f) => {
                let receipt = match &f.evidence {
                    native_archive::Evidence::Receive { receipt, .. }
                    | native_archive::Evidence::Status { receipt, .. } => receipt,
                };
                vec![
                    own_signatures(&f.own[2], &f.own[0], &f.own[1], root)?,
                    vec![signature(
                        ObjectKind::Receipt,
                        receipt,
                        key(&f.retained.signed[3], CREDENTIAL_KEY)?,
                    )?],
                ]
            }
            Self::Consuming(f) => vec![own_signatures(
                &f.objects[2],
                &f.objects[0],
                &f.objects[1],
                root,
            )?],
            Self::Refresh(f) => {
                let kind = match variant {
                    Variant::RefreshCredential => ObjectKind::Credential,
                    Variant::RefreshSchemePolicy => ObjectKind::SchemePolicy,
                    Variant::RefreshBlacklist => ObjectKind::Blacklist,
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
            Self::Bootstrap(f) => attach!(f, bootstrap, 2, Bootstrap),
            Self::Load(f) => attach!(f, load, 3, Load),
            Self::Send(f) => attach!(f, send, 2, Send),
            Self::Receive(f) => attach!(f, receive, 3, Receive),
            Self::Archive(f) => attach!(f, native_archive, 3, Archive),
            Self::Consuming(f) => attach!(f, consuming, 2, Consuming),
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
        let actual = selected.finish(&step.frozen.capsule.successor_state)?;
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
        if (step.frozen.capsule.kind == KagemushaWalletOperationKindV1::Bootstrap)
            != predecessor.is_none()
            || custody.predecessor().is_some() != predecessor.is_some()
        {
            return Err(Error::WitnessLost("fold schedule predecessor"));
        }
        self.route_schedule(selector(step)?)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn next(
        &self,
        step: &ReleasedStep,
        predecessor: Option<&KagemushaWalletFoldRecordV1>,
        checkpoints: &[Vec<u8>],
        cancellation: &Cancellation,
        originals: &mut dyn OriginalSourceV1,
        custody: &mut FoldCustodyV1<'_>,
    ) -> Result<FoldProgress, Error> {
        cancellation.check()?;
        let route = selector(step)?;
        let schedule = self.schedule(step, predecessor, custody)?;
        if checkpoints.len() > schedule.len() {
            return Err(Error::Proof("native checkpoint count"));
        }
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
        let state = &step.frozen.capsule.successor_state;
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
                Fields::Load(proof(preparation.load_fold_fields(
                    &owner,
                    step,
                    folded.as_ref().ok_or(Error::FoldRequired)?,
                    &public,
                    self.budget,
                ))?)
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
                    step.frozen.capsule.statement.effect
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
                    KagemushaWalletPolicyUpdateKindV1::Blacklist => {
                        PreparationOriginalV1::Blacklist
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
        let own_key = self
            .sources
            .sigmas()
            .key(route.own)
            .ok_or(Error::Proof("own sigma selector"))?;
        let sigma = &step.frozen.capsule.step_proof.bytes;
        let q_sources = q::QSourcesV1 {
            own: SigmaSlotWitness {
                key: own_key.key().clone(),
                statement: Option::<Fp>::from(Fp::from_repr(valid(
                    step.frozen.capsule.statement.statement_digest(),
                )?))
                .ok_or(Error::Invalid("statement field"))?,
                proof: sigma.clone(),
                length: u32::try_from(sigma.len()).map_err(|_| Error::Invalid("sigma length"))?,
            },
            incoming,
            signatures: fields.signatures([root.x, root.y], route.variant)?,
        };
        let q_count = proof(self.sources.q(route))?.keys().len();
        let q = match self.q_stage(
            route,
            valid(step.frozen.capsule.capsule_digest())?,
            &q_sources,
            &checkpoints[..checkpoints.len().min(q_count)],
            originals,
            cancellation,
        )? {
            q::QProgressV1::Checkpoint(bytes) => return Ok(FoldProgress::Checkpoint(bytes)),
            q::QProgressV1::Complete(q) => q,
        };
        let public_fields = proof(preparation.state_fields(&owner, state, &public))?.lineage;
        match self.stage(
            route,
            fields.with_q(q)?,
            public_fields,
            &checkpoints[q_count..],
            originals,
            cancellation,
        )? {
            NativeStageProgressV1::Checkpoint(bytes) => Ok(FoldProgress::Checkpoint(bytes)),
            NativeStageProgressV1::Terminal(input) => {
                let proof_bytes = self.finish(input, originals, cancellation)?;
                let lineage = KagemushaWalletLineageV1 {
                    public,
                    proof: proof_bytes,
                };
                proof(self.installed.verifier().verify_lineage_cancellable(
                    &lineage,
                    self.budget,
                    Some(cancellation.prover_token()),
                ))?;
                let burned =
                    route.variant == Variant::Receive || route.variant == Variant::ReceiveRenewed;
                let burned = burned
                    && public.burned_total
                        != predecessor
                            .ok_or(Error::FoldRequired)?
                            .lineage
                            .public
                            .burned_total;
                Ok(FoldProgress::Complete { lineage, burned })
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
            for carried_controls in [0, 1, 7, 8, u32::MAX] {
                let KagemushaWalletLineageSlotV1::Present { lineage } = &mut payment.send.lineage
                else {
                    panic!("fixture lineage");
                };
                lineage.public.enabled_controls = carried_controls;
                assert_eq!(
                    incoming_send_selector(&payment).unwrap(),
                    2 + if carried_controls <= 7 {
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
        let mut objects: [Vec<u8>; 11] = std::array::from_fn(|_| Vec::new());
        for (index, kind) in [
            (0, ObjectKind::Request),
            (1, ObjectKind::Credential),
            (2, ObjectKind::Receipt),
            (9, ObjectKind::Credential),
            (10, ObjectKind::Certificate),
        ] {
            objects[index] = vec![u8::try_from(index + 1).unwrap(); kind.body_len() + 64];
        }
        let root = [[7; 4]; 2];
        let normal = receive_signatures(&objects, false, root).unwrap();
        let renewed = receive_signatures(&objects, true, root).unwrap();
        assert_eq!(normal.len(), 2);
        assert_eq!(renewed.len(), 4);
        assert_eq!(renewed[0].key, key(&objects[1], CREDENTIAL_KEY).unwrap());
        assert_eq!(renewed[1].key, key(&objects[9], CREDENTIAL_KEY).unwrap());
        assert_eq!(renewed[2].key, key(&objects[10], CERTIFICATE_KEY).unwrap());
        assert_eq!(renewed[3].key, root);
        assert_eq!(normal[0].digest, renewed[0].digest);
        assert_eq!(normal[1].digest, renewed[1].digest);
        objects[9].push(0);
        assert!(receive_signatures(&objects, true, root).is_err());
    }
}
