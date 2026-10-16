//! Exact Q source derivation, self-verifying proof tasks and original restoration.

use crate::kagemusha_wallet_artifacts_v1::producer_inventory::ImportedQV1;
use iroha_kagemusha_proof::{
    q_sigma::{
        SigmaSlotWitness,
        native::{IncomingSigma, QSigmaFoldSource},
    },
    q_signature::SignatureWitness,
};

use super::*;

/// Raw source witnesses reconstructed from exact selected custody originals.
/// The installed Q plan independently binds keys, derives verdicts and decides claims.
pub(super) struct QSourcesV1 {
    pub(super) own: SigmaSlotWitness,
    pub(super) incoming: Option<IncomingSigma>,
    pub(super) signatures: Vec<Vec<SignatureWitness>>,
}

pub(super) enum QProgressV1 {
    Checkpoint(PrivateArchiveBytes),
    Complete(Vec<q_checkpoint::Original>),
}

impl NativeFoldWorkerV1 {
    /// Restore each exact source Q and produce one next Q proof with the Q source whose
    /// originals the locked prepare revalidated. `source` is the custody digest of the
    /// selected immutable capsule, the private checkpoint identity. A restored incoming Q uses
    /// its exact retained fold witness; only a new incoming Q obtains fresh private coins.
    pub(super) fn q_stage(
        &self,
        route: OperationRoute,
        source: [u8; 32],
        input: &QSourcesV1,
        checkpoints: &[PrivateArchiveBytes],
        cancellation: &Cancellation,
    ) -> Result<QProgressV1, Error> {
        cancellation.check()?;
        fold_metrics::enter(FoldPhaseV1::Restore);
        let q = proof(self.sources.q(route))?;
        if source == [0; 32]
            || input.signatures.len() != q.signatures().len()
            || checkpoints.len() > q.keys().len()
        {
            return Err(Error::Proof("Q source schedule"));
        }
        let params = proof(self.installed.verifier().vesta_parameters(16))?;
        let q_params = self.installed.verifier().pallas_parameters();
        let requires_fold = q.sigma().requires_private_fold();
        let mut prior_sigma = checkpoints
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
            .transpose()?;
        let fold_source = if requires_fold {
            if let Some(prior) = prior_sigma.as_ref() {
                QSigmaFoldSource::Retained(
                    prior
                        .private_fold
                        .as_ref()
                        .ok_or(Error::Proof("missing retained Q fold"))?,
                )
            } else {
                QSigmaFoldSource::Fresh(fresh_fold_tape::<Eq>(cancellation.prover_token())?)
            }
        } else {
            QSigmaFoldSource::NoIncoming
        };
        let sigma = proof(q.sigma().prepare(
            input.own.clone(),
            input.incoming.clone(),
            params,
            fold_source,
            &self.fold_config(cancellation),
        ))?;
        let mut expected = vec![sigma.instances().to_vec()];
        for (plan, witnesses) in q.signatures().iter().zip(&input.signatures) {
            cancellation.check()?;
            expected.push(proof(plan.native_instances(witnesses))?.to_vec());
        }
        let mut checked = Vec::with_capacity(checkpoints.len());
        for (stage, bytes) in checkpoints.iter().enumerate() {
            cancellation.check()?;
            let original = if stage == 0 {
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
            if original.instances != expected[stage] {
                return Err(Error::Proof("Q changed source instance"));
            }
            checked.push(original);
        }
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
            cancellation.check()?;
            fold_metrics::enter(FoldPhaseV1::Prove);
            match owner {
                ImportedQV1::Sigma(owner) if stage == 0 => {
                    let output = proof(owner.prove(
                        &sigma,
                        ProverRandomness::os(),
                        self.prover_config(cancellation),
                    ))?;
                    q_checkpoint::Original {
                        proof: output.bytes,
                        instances: output.instances,
                        private_fold: sigma.retained_fold().cloned(),
                    }
                }
                ImportedQV1::Signature(owner) if stage > 0 => {
                    let output = proof(owner.prove(
                        &input.signatures[stage - 1],
                        ProverRandomness::os(),
                        self.prover_config(cancellation),
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
            stage == 0 && requires_fold,
            self.budget,
            cancellation,
        )?;
        cancellation.check()?;
        Ok(QProgressV1::Checkpoint(bytes))
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
