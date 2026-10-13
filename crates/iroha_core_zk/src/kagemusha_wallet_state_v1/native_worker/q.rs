//! Exact Q source derivation, self-verifying proof tasks and original restoration.

use crate::kagemusha_wallet_artifacts_v1::producer_inventory::ImportedQV1;
use iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRecoveryCapsuleV1;
use iroha_kagemusha_proof::{
    q_sigma::{SigmaSlotWitness, native::IncomingSigma},
    q_signature::SignatureWitness,
};
use iroha_plonk_gadgets::bytes::p_bytes_native;

use super::*;

/// Raw source witnesses reconstructed from exact selected custody originals.
/// The installed Q plan independently binds keys, derives verdicts and decides claims.
pub(super) struct QSourcesV1 {
    pub(super) own: SigmaSlotWitness,
    pub(super) incoming: Option<IncomingSigma>,
    pub(super) signatures: Vec<Vec<SignatureWitness>>,
}

pub(super) enum QProgressV1 {
    Checkpoint(Vec<u8>),
    Complete(Vec<q_checkpoint::Original>),
}

/// Public deterministic nonce for Q's non-hiding local fold, never fresh entropy.
/// The immutable owner couples this commitment to the private custody digest;
/// caller preparation has already verified its retained completion and receipt.
fn local_fold_nonce(capsule: &KagemushaWalletRecoveryCapsuleV1) -> Fq {
    p_bytes_native::<Fq>(
        u64::from_le_bytes(*b"kgwqnon1"),
        &capsule.receipt_commitment(),
    )
}

impl NativeFoldWorkerV1 {
    /// Restore each exact source Q and produce one next Q proof. The selected immutable
    /// capsule supplies both its private checkpoint identity and public nonce commitment;
    /// neither is an independent caller tag. Preparation has verified the matching receipt.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn q_stage(
        &self,
        route: OperationRoute,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        input: &QSourcesV1,
        checkpoints: &[Vec<u8>],
        originals: &mut dyn OriginalSourceV1,
        cancellation: &Cancellation,
    ) -> Result<QProgressV1, Error> {
        cancellation.check()?;
        let q = proof(self.sources.q(route))?;
        let source = capsule.custody_digest();
        if source == [0; 32]
            || input.signatures.len() != q.signatures().len()
            || checkpoints.len() > q.keys().len()
        {
            return Err(Error::Proof("Q source schedule"));
        }
        let params = proof(self.installed.verifier().vesta_parameters(16))?;
        let q_params = self.installed.verifier().pallas_parameters();
        // This query depends only on the signed public commitment, never private h.
        // Repeating exact W repeats this public nonce; zero is a valid derived salt.
        // Q absorbs it and every ordered input before its fold challenges. It supplies
        // no fresh private entropy. Proof hiding still uses fresh OS randomness, while
        // an existing checkpoint must return its verified original proof bytes.
        let salt = local_fold_nonce(capsule);
        let sigma = proof(q.sigma().prepare(
            input.own.clone(),
            input.incoming.clone(),
            params,
            salt,
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
            checked.push(q_checkpoint::restore(
                &q.keys()[stage],
                q_params,
                stage,
                source,
                bytes,
                &expected[stage],
                self.budget,
                cancellation,
            )?);
        }
        cancellation.check()?;
        if checkpoints.len() == q.keys().len() {
            return Ok(QProgressV1::Complete(checked));
        }
        let stage = checkpoints.len();
        let original = {
            let owner = self
                .sources
                .import_q_cancellable(
                    route,
                    stage,
                    originals,
                    self.read,
                    Some(cancellation.prover_token()),
                )
                .map_err(artifact)?;
            cancellation.check()?;
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
            self.budget,
            cancellation,
        )?;
        cancellation.check()?;
        Ok(QProgressV1::Checkpoint(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_state_v1::tests::fixture;
    use iroha_data_model::kagemusha::kagemusha_wallet_v1::{
        KagemushaWalletCompletionRecordV1, KagemushaWalletRequestV1,
        KagemushaWalletRetainedInputRoleV1,
    };

    // Signed shared DATA fixtures exercise the immutable owner and receipt/custody joins.
    // Stand-in sigma/Omega bytes do not establish an actual Q proof or C12 privacy.
    #[test]
    fn q_nonce_uses_public_commitment_and_restores_exactly() {
        let capsule: KagemushaWalletRecoveryCapsuleV1 = fixture("KagemushaWalletRecoveryCapsuleV1");
        let domain = u64::from_le_bytes(*b"kgwqnon1");
        let nonce = local_fold_nonce(&capsule);
        assert_eq!(
            nonce,
            p_bytes_native::<Fq>(domain, &capsule.receipt_commitment())
        );
        assert_ne!(
            nonce,
            p_bytes_native::<Fq>(domain, &capsule.custody_digest())
        );
        let bytes = capsule.to_canonical_bytes();
        let restored =
            KagemushaWalletRecoveryCapsuleV1::decode_canonical(&bytes, &capsule.body().scheme_id)
                .unwrap();
        assert_eq!(restored.to_canonical_bytes(), bytes);
        assert_eq!(restored.custody_digest(), capsule.custody_digest());
        assert_eq!(local_fold_nonce(&restored), nonce);

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
            assert_ne!(local_fold_nonce(&changed), nonce);
            assert_eq!(
                local_fold_nonce(&changed),
                p_bytes_native::<Fq>(domain, &changed.receipt_commitment())
            );
        }
    }

    #[test]
    fn q_nonce_source_keeps_private_and_public_completion_joins_distinct() {
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
        assert_ne!(local_fold_nonce(&changed), local_fold_nonce(&capsule));
    }
}
