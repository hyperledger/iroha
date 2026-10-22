//! Exact Q source derivation, self-verifying proof tasks and original restoration.

use crate::kagemusha_wallet_artifacts_v1::producer_inventory::ImportedQV1;
use iroha_kagemusha_proof::{
    q_sigma::{
        SigmaSlotWitness,
        native::{IncomingSigma, PreparedQSigma, QSigmaFoldSource},
    },
    q_signature::SignatureWitness,
};

use super::*;

/// Raw source witnesses reconstructed from exact selected custody originals.
/// The installed Q plan independently binds keys, derives verdicts and decides claims.
pub(super) struct QSourcesV1 {
    /// The own sigma witness, absent on a route whose A proves the own step directly
    /// (every route but Refresh); Receive and `ArchiveReceive` keep an incoming one.
    pub(super) own: Option<SigmaSlotWitness>,
    pub(super) incoming: Option<IncomingSigma>,
    pub(super) signatures: Vec<Vec<SignatureWitness>>,
}

/// The Q chain one sub-proof leaves for the next sub-proof of its step (D6b): the σ
/// preparation in restore form, the expected frame of every Q source, and the durable Q
/// originals restored so far. Never a σ preparation from fresh coins, and never the Q proof a
/// sub-proof produced; that proof enters the next sub-proof through its durable bytes.
pub(super) struct QStateV1 {
    /// Prepared from `NoIncoming`, or from the private fold of durable checkpoint 0. Absent
    /// on a route without `Q_sigma` (lean lineage), whose Q chain is signature leaves only.
    sigma: Option<PreparedQSigma>,
    expected: Vec<Vec<Vec<Fq>>>,
    checked: Vec<q_checkpoint::Original>,
}
impl QStateV1 {
    /// How many durable Q checkpoints this state restored.
    pub(super) fn restored(&self) -> usize {
        self.checked.len()
    }
}

/// Whether a σ preparation is in restore form and may be retained for the next sub-proof:
/// prepared from `NoIncoming`, or from the private fold of durable checkpoint 0. One prepared
/// from fresh coins, before any Q checkpoint is durable, never is.
pub(super) const fn sigma_in_restore_form(requires_fold: bool, durable_q0: bool) -> bool {
    !requires_fold || durable_q0
}

pub(super) enum QProgressV1 {
    /// The next Q proof, and the Q chain the next sub-proof may resume: `None` when σ was
    /// prepared from fresh coins.
    Checkpoint(PrivateArchiveBytes, Option<Box<QStateV1>>),
    Complete(Vec<q_checkpoint::Original>),
}

impl NativeFoldWorkerV1 {
    /// Restore each exact source Q and produce one next Q proof with the Q source whose
    /// originals the locked prepare revalidated. `source` is the custody digest of the
    /// selected immutable capsule, the private checkpoint identity. A restored incoming Q uses
    /// its exact retained fold witness; only a new incoming Q obtains fresh private coins.
    ///
    /// `retained` is the Q chain the previous sub-proof of this step left, whose restored
    /// payloads the locked prepare matched as a byte-exact prefix of `checkpoints`: only the
    /// durable Q checkpoints beyond it are restored, strictly from their bytes.
    /// A route without `Q_sigma` (lean lineage) has only signature leaves, from Q0.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn q_stage(
        &self,
        route: OperationRoute,
        source: [u8; 32],
        input: &QSourcesV1,
        checkpoints: &[PrivateArchiveBytes],
        retained: Option<Box<QStateV1>>,
        cancellation: &Cancellation,
    ) -> Result<QProgressV1, Error> {
        cancellation.check()?;
        fold_metrics::enter(FoldPhaseV1::Restore);
        let q = proof(self.sources.q(route))?;
        let offset = q.signature_offset();
        if source == [0; 32]
            || input.signatures.len() != q.signatures().len()
            || checkpoints.len() > q.keys().len()
            || input.own.is_some() != q.sigma().is_some_and(|sigma| sigma.has_own())
        {
            return Err(Error::Proof("Q source schedule"));
        }
        let q_params = self.installed.verifier().pallas_parameters();
        let requires_fold = q.sigma().is_some_and(|sigma| sigma.requires_private_fold());
        let (sigma, expected, checked, retains) = if let Some(state) =
            retained.filter(|state| state.checked.len() <= checkpoints.len())
        {
            let QStateV1 {
                sigma,
                expected,
                mut checked,
            } = *state;
            for (stage, bytes) in checkpoints.iter().enumerate().skip(checked.len()) {
                cancellation.check()?;
                let original = q_checkpoint::restore(
                    &q.keys()[stage],
                    q_params,
                    stage,
                    source,
                    bytes,
                    &expected[stage],
                    stage < offset && requires_fold,
                    self.budget,
                    cancellation,
                )?;
                #[cfg(test)]
                super::retention::count(|counts| counts.restores += 1);
                if original.instances != expected[stage] {
                    return Err(Error::Proof("Q changed source instance"));
                }
                checked.push(original);
            }
            (sigma, expected, checked, true)
        } else {
            let params = proof(self.installed.verifier().vesta_parameters(16))?;
            let mut prior_sigma = if offset == 1 {
                checkpoints
                    .first()
                    .map(|bytes| {
                        q_checkpoint::read_verified(
                            &q.keys()[0],
                            q_params,
                            0,
                            source,
                            bytes,
                            requires_fold,
                            self.budget,
                            cancellation,
                        )
                    })
                    .transpose()?
            } else {
                None
            };
            let retains = sigma_in_restore_form(requires_fold, prior_sigma.is_some());
            #[cfg(test)]
            super::retention::count(|counts| {
                counts.sigmas += u64::from(q.sigma().is_some());
                counts.fresh_sigmas += u64::from(!retains);
            });
            let sigma = match q.sigma() {
                Some(plan) => {
                    let fold_source = if requires_fold {
                        if let Some(prior) = prior_sigma.as_ref() {
                            QSigmaFoldSource::Retained(
                                prior
                                    .private_fold
                                    .as_ref()
                                    .ok_or(Error::Proof("missing retained Q fold"))?,
                            )
                        } else {
                            QSigmaFoldSource::Fresh(fresh_fold_tape::<Eq>(
                                cancellation.prover_token(),
                            )?)
                        }
                    } else {
                        QSigmaFoldSource::NoIncoming
                    };
                    Some(proof(plan.prepare(
                        input.own.clone(),
                        input.incoming.clone(),
                        params,
                        fold_source,
                        &self.fold_config(cancellation),
                    ))?)
                }
                None => None,
            };
            let mut expected = Vec::with_capacity(q.keys().len());
            if let Some(sigma) = &sigma {
                expected.push(sigma.instances().to_vec());
            }
            for (plan, witnesses) in q.signatures().iter().zip(&input.signatures) {
                cancellation.check()?;
                expected.push(proof(plan.native_instances(witnesses))?.to_vec());
            }
            let mut checked = Vec::with_capacity(checkpoints.len());
            for (stage, bytes) in checkpoints.iter().enumerate() {
                cancellation.check()?;
                let original = if stage < offset {
                    prior_sigma
                        .take()
                        .ok_or(Error::Proof("missing Q checkpoint"))?
                } else {
                    q_checkpoint::restore(
                        &q.keys()[stage],
                        q_params,
                        stage,
                        source,
                        bytes,
                        &expected[stage],
                        false,
                        self.budget,
                        cancellation,
                    )?
                };
                #[cfg(test)]
                super::retention::count(|counts| counts.restores += 1);
                if original.instances != expected[stage] {
                    return Err(Error::Proof("Q changed source instance"));
                }
                checked.push(original);
            }
            (sigma, expected, checked, retains)
        };
        cancellation.check()?;
        if checkpoints.len() == q.keys().len() {
            return Ok(QProgressV1::Complete(checked));
        }
        let stage = checkpoints.len();
        let original = {
            let owner = self
                .sources
                .bind_q_cancellable(route, stage, self.read, Some(cancellation.prover_token()))
                .map_err(artifact)?;
            let config = self.prover_config(cancellation, owner.binding().descriptor());
            cancellation.check()?;
            fold_metrics::enter(FoldPhaseV1::Prove);
            match (owner, &sigma) {
                (ImportedQV1::Sigma(owner), Some(sigma)) if stage < offset => {
                    let output = proof(owner.prove(sigma, ProverRandomness::os(), config))?;
                    q_checkpoint::Original {
                        proof: output.bytes,
                        instances: output.instances,
                        private_fold: sigma.retained_fold().cloned(),
                    }
                }
                (ImportedQV1::Signature(owner), _) if stage >= offset => {
                    let output = proof(owner.prove(
                        &input.signatures[stage - offset],
                        ProverRandomness::os(),
                        config,
                    ))?;
                    q_checkpoint::Original {
                        proof: output.bytes,
                        instances: output.instances.to_vec(),
                        private_fold: None,
                    }
                }
                _ => return Err(Error::Proof("Q native role")),
            }
        };
        if original.instances != expected[stage] {
            return Err(Error::Proof("Q native source values"));
        }
        let bytes = q_checkpoint::encode(
            &q.keys()[stage],
            q_params,
            stage,
            source,
            &original,
            stage < offset && requires_fold,
            self.budget,
            cancellation,
        )?;
        cancellation.check()?;
        // The produced proof is never retained: the next sub-proof restores it from its
        // durable bytes. What is retained was restored or prepared in restore form.
        drop(original);
        let kept = retains.then(|| {
            Box::new(QStateV1 {
                sigma,
                expected,
                checked,
            })
        });
        Ok(QProgressV1::Checkpoint(bytes, kept))
    }
}

/// Countersign Z1(4) one level down, for the retention module's type check: an exhaustive
/// destructuring of the retained Q chain and of each restored Q original, with explicit field
/// types, so a new field fails to compile here. The plain bytes are the proof bytes the strict
/// restores decoded into the originals and the σ proofs inside the σ preparation, as during a
/// call; every private fold stays in `PrivateFoldBytes`.
#[cfg(test)]
pub(super) fn q_state_fields(state: QStateV1) {
    let QStateV1 {
        sigma,
        expected,
        checked,
    } = state;
    let _: Option<PreparedQSigma> = sigma;
    let _: Vec<Vec<Vec<Fq>>> = expected;
    for original in checked {
        let q_checkpoint::Original {
            proof,
            instances,
            private_fold,
        } = original;
        let _: Vec<u8> = proof;
        let _: Vec<Vec<Fq>> = instances;
        let _: Option<iroha_kagemusha_proof::private_fold::PrivateFoldBytes> = private_fold;
    }
}

#[cfg(test)]
mod tests {
    use crate::kagemusha_wallet_state_v1::tests::fixture;
    use iroha_data_model::kagemusha::kagemusha_wallet_v1::{
        KagemushaWalletCompletionRecordV1, KagemushaWalletRecoveryCapsuleV1,
        KagemushaWalletRequestV1, KagemushaWalletRetainedInputRoleV1,
    };

    // Signed shared DATA fixtures exercise the immutable owner and receipt/custody joins.
    // Stand-in sigma/Omega bytes do not establish an actual Q proof or C12 privacy.
    #[test]
    fn q_retained_source_restores_exactly_without_a_public_nonce() {
        let capsule: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
        let bytes = capsule.to_canonical_bytes();
        let restored =
            KagemushaWalletRecoveryCapsuleV1::decode_canonical(&bytes, &capsule.body().scheme_id)
                .unwrap();
        assert_eq!(restored.to_canonical_bytes(), bytes);
        assert_eq!(restored.custody_digest(), capsule.custody_digest());
        assert_eq!(restored.receipt_commitment(), capsule.receipt_commitment());

        // Test-only resealing creates distinct original owners; production restoration
        // never samples or reseals. Canonical opening zero remains accepted.
        let mut one = [0; 32];
        one[0] = 1;
        for opening in [[0; 32], one] {
            let changed = capsule
                .body()
                .clone()
                .freeze()
                .unwrap()
                .seal(opening)
                .unwrap();
            assert_eq!(changed.body(), capsule.body());
            assert_ne!(changed.custody_digest(), capsule.custody_digest());
            assert_ne!(changed.receipt_commitment(), capsule.receipt_commitment());
        }
    }

    #[test]
    fn q_source_keeps_private_and_public_completion_joins_distinct() {
        let capsule: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
        let completion: KagemushaWalletCompletionRecordV1 =
            fixture("KagemushaWalletCompletionRecordV1");
        let original = capsule
            .body()
            .retained_inputs
            .iter()
            .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::Request)
            .expect("exact retained Request original");
        let request: KagemushaWalletRequestV1 = norito::decode_canonical_with_limits(
            &original.bytes,
            norito::canonical_decode_limits(original.bytes.len()),
        )
        .expect("canonical retained Request");
        request.validate().expect("signed retained Request");
        assert_eq!(request.body.scheme_id, capsule.body().scheme_id);
        let credential = &request.receiver_credential;
        completion
            .verify(credential, &capsule)
            .expect("signed fixture authority");
        completion.require_capsule(&capsule).unwrap();
        assert_eq!(completion.capsule_digest, capsule.custody_digest());
        assert_eq!(
            completion.receipt.capsule_commitment,
            capsule.receipt_commitment()
        );
        assert_ne!(
            completion.capsule_digest,
            completion.receipt.capsule_commitment
        );

        let changed = capsule
            .body()
            .clone()
            .freeze()
            .unwrap()
            .seal([0; 32])
            .unwrap();
        assert_eq!(changed.body(), capsule.body());
        assert!(completion.require_capsule(&changed).is_err());
        // Replacing only h cannot authorize another public d or the old receipt.
        let mut swapped = completion.clone();
        swapped.capsule_digest = changed.custody_digest();
        assert!(swapped.require_capsule(&changed).is_err());
        assert!(swapped.verify(credential, &changed).is_err());
        // The converse must fail too: a correct new d cannot replace private source h.
        let mut swapped = completion.clone();
        swapped.receipt.capsule_commitment = changed.receipt_commitment();
        assert!(swapped.require_capsule(&changed).is_err());
        assert!(swapped.verify(credential, &changed).is_err());
        // A structurally joined pair still cannot authenticate changed receipt/output bytes.
        swapped.capsule_digest = changed.custody_digest();
        swapped.require_capsule(&changed).unwrap();
        assert!(swapped.verify(credential, &changed).is_err());
        assert_ne!(changed.custody_digest(), capsule.custody_digest());
    }
}
