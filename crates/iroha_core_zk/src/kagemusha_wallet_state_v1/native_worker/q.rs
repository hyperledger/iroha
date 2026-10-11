//! Exact Q source derivation, self-verifying proof tasks and original restoration.

use crate::kagemusha_wallet_artifacts_v1::producer_inventory::ImportedQV1;
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

impl NativeFoldWorkerV1 {
    /// Restore each exact source Q and produce one next Q proof. The source digest
    /// is the selected released capsule identity, never a caller's free checkpoint tag.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn q_stage(
        &self,
        route: OperationRoute,
        source: [u8; 32],
        input: &QSourcesV1,
        checkpoints: &[Vec<u8>],
        originals: &mut dyn OriginalSourceV1,
        cancellation: &Cancellation,
    ) -> Result<QProgressV1, Error> {
        cancellation.check()?;
        let q = proof(self.sources.q(route))?;
        if source == [0; 32]
            || input.signatures.len() != q.signatures().len()
            || checkpoints.len() > q.keys().len()
        {
            return Err(Error::Proof("Q source schedule"));
        }
        let params = proof(self.installed.verifier().vesta_parameters(16))?;
        let q_params = self.installed.verifier().pallas_parameters();
        // Repeating the same released capsule uses the same public local-fold
        // nonce. Proof hiding still uses fresh OS randomness; the retained exact
        // proof wins after checkpoint publication and is never regenerated there.
        let salt = p_bytes_native::<Fq>(u64::from_le_bytes(*b"kgwqnon1"), &source);
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
