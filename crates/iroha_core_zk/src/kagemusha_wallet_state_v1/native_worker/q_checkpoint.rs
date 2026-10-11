//! Bounded canonical Q originals with strict installed verification on restoration.

use iroha_kagemusha_proof::a_relation::native::artifact::KeyArtifact;
use iroha_pasta::Ep;
use iroha_plonk::{Protocol, pcs::ipa::PinnedParams, verifier::verify_full_cancellable};
use norito::{NoritoDeserialize, NoritoSchema, NoritoSerialize};

use super::*;

#[derive(NoritoSerialize, NoritoDeserialize, NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.wallet.q_checkpoint.v1")]
struct Payload {
    version: u16,
    stage: u32,
    descriptor: [u8; 32],
    key: [u8; 32],
    source: [u8; 32],
    proof: Vec<u8>,
    instances: Vec<Vec<[u8; 32]>>,
}

pub(super) struct Layout {
    pub(super) custody: CheckpointLayout,
    stage: u32,
    descriptor: [u8; 32],
    key: [u8; 32],
    proof_bytes: usize,
    columns: Vec<usize>,
}
impl Layout {
    pub(super) fn new(stage: usize, key: &KeyArtifact<Ep>) -> Result<Self, Error> {
        let stage = u32::try_from(stage).map_err(|_| Error::Proof("Q ordinal"))?;
        let descriptor = *key.binding().digest();
        let digest = proof(key.key().kagemusha_digest(key.binding()))?.to_repr();
        let proof_bytes = proof(Protocol::new(key.binding().descriptor()))?.proof_length();
        let columns = key
            .binding()
            .descriptor()
            .instance_lengths
            .iter()
            .map(|n| *n as usize)
            .collect::<Vec<_>>();
        let specimen = Payload {
            version: 1,
            stage,
            descriptor,
            key: digest,
            source: [0; 32],
            proof: vec![0; proof_bytes],
            instances: columns.iter().map(|n| vec![[0; 32]; *n]).collect(),
        };
        let bytes = proof(norito::canonical_frame_len(&specimen))?;
        Ok(Self {
            custody: layout(&descriptor, &digest, 1, stage, bytes)?,
            stage,
            descriptor,
            key: digest,
            proof_bytes,
            columns,
        })
    }
    fn check(&self, payload: &Payload, source: [u8; 32]) -> Result<(), Error> {
        if payload.version != 1
            || payload.stage != self.stage
            || payload.descriptor != self.descriptor
            || payload.key != self.key
            || payload.source != source
            || payload.proof.len() != self.proof_bytes
            || payload.instances.len() != self.columns.len()
            || payload
                .instances
                .iter()
                .zip(&self.columns)
                .any(|(column, n)| column.len() != *n)
        {
            return Err(Error::Proof("Q checkpoint binding"));
        }
        Ok(())
    }
    fn decode(&self, bytes: &[u8], source: [u8; 32]) -> Result<Payload, Error> {
        if bytes.len() != self.custody.payload_bytes as usize {
            return Err(Error::Proof("Q checkpoint length"));
        }
        let payload = proof(norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        ))?;
        self.check(&payload, source)?;
        Ok(payload)
    }
}

/// Original Q evidence, still bound and fully verified against the selected metadata.
pub(super) struct Original {
    pub(super) proof: Vec<u8>,
    pub(super) instances: Vec<Vec<Fq>>,
}

pub(super) fn encode(
    key: &KeyArtifact<Ep>,
    params: &PinnedParams<Ep>,
    stage: usize,
    source: [u8; 32],
    original: &Original,
    budget: MemoryBudget,
    cancellation: &Cancellation,
) -> Result<Vec<u8>, Error> {
    cancellation.check()?;
    let layout = Layout::new(stage, key)?;
    let payload = Payload {
        version: 1,
        stage: layout.stage,
        descriptor: layout.descriptor,
        key: layout.key,
        source,
        proof: original.proof.clone(),
        instances: original
            .instances
            .iter()
            .map(|c| c.iter().map(PrimeField::to_repr).collect())
            .collect(),
    };
    layout.check(&payload, source)?;
    proof(verify_full_cancellable(
        params,
        key.binding(),
        key.key(),
        &original.instances,
        &original.proof,
        budget,
        Some(cancellation.prover_token()),
    ))?;
    let bytes = proof(norito::encode_canonical(&payload))?;
    if bytes.len() != layout.custody.payload_bytes as usize {
        return Err(Error::Proof("Q checkpoint encoding"));
    }
    Ok(bytes)
}

#[allow(
    clippy::too_many_arguments,
    reason = "exact checkpoint identity and borrowed installed verifier parameters remain explicit"
)]
pub(super) fn restore(
    key: &KeyArtifact<Ep>,
    params: &PinnedParams<Ep>,
    stage: usize,
    source: [u8; 32],
    bytes: &[u8],
    expected: &[Vec<Fq>],
    budget: MemoryBudget,
    cancellation: &Cancellation,
) -> Result<Original, Error> {
    cancellation.check()?;
    let payload = Layout::new(stage, key)?.decode(bytes, source)?;
    let instances = payload
        .instances
        .into_iter()
        .map(|column| {
            column
                .into_iter()
                .map(|word| {
                    Option::<Fq>::from(Fq::from_repr(word))
                        .ok_or(Error::Proof("Q noncanonical instance"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    if instances != expected {
        return Err(Error::Proof("Q changed source instance"));
    }
    proof(verify_full_cancellable(
        params,
        key.binding(),
        key.key(),
        &instances,
        &payload.proof,
        budget,
        Some(cancellation.prover_token()),
    ))?;
    Ok(Original {
        proof: payload.proof,
        instances,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_proof_checkpoint_uses_borrowed_parameters_and_refuses_foreign_context() {
        use ff::Field;
        use iroha_plonk::{
            ProvingKey,
            cs::{Column, ConstraintSystem, Instance, InstanceType},
            frontend::{Circuit, Error as SynthesisError, Layouter, SimpleFloorPlanner},
            keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2},
            prover::{Witness, create_proof_owned},
        };
        use iroha_plonk_gadgets::{GlueChip, GlueConfig};

        // An actual small PIPA-R proof exercises this storage boundary. It is
        // neither the wallet's fixed Q relation nor an authenticated source grant.
        #[derive(Clone)]
        struct CircuitFixture;
        impl Circuit<Fq> for CircuitFixture {
            type Config = (GlueConfig, Column<Instance>);
            type Params = ();
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self
            }
            fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
                let advice = core::array::from_fn(|_| meta.advice_column());
                let fixed = meta.fixed_column();
                let glue = GlueConfig::configure(meta, advice, fixed);
                let public = meta.instance_column(1);
                meta.enable_equality(public);
                (glue, public)
            }
            fn synthesize(
                &self,
                (glue, public): Self::Config,
                mut layouter: impl Layouter<Fq>,
            ) -> Result<(), SynthesisError> {
                let cell = layouter.assign_region(
                    || "checkpoint original",
                    |mut region| GlueChip::new(glue).constant(&mut region, Fq::ONE),
                )?;
                layouter.constrain_instance(cell.cell(), public, 0)
            }
        }
        let params = PinnedParams::<Ep>::derive(8).unwrap();
        let mut config = KeygenConfigV2::pipa_r(vec![InstanceType::Field]);
        config.coset_cache = CosetCachePolicy::OnDemand;
        let generated = keygen_pk_v2(&params, &CircuitFixture, &config).unwrap();
        let metadata =
            KeyArtifact::new(generated.binding().clone(), generated.vk().clone()).unwrap();
        let original = generated.artifact_bytes_v2().unwrap();
        drop(generated);
        let read = iroha_plonk::keys::pk::artifact::ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 1 << 8,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        let imported = ProvingKey::from_artifact_v2(
            &original,
            metadata.binding(),
            &params,
            &CircuitFixture,
            read,
        )
        .unwrap();
        metadata.require_prover(&imported).unwrap();
        let instances = vec![vec![Fq::ONE]];
        let witness = Witness::from_circuit(&imported, &CircuitFixture, &instances).unwrap();
        let proof = create_proof_owned(
            &params,
            &imported,
            witness,
            ProverRandomness::hedged(),
            ProverConfig::default(),
        )
        .unwrap();
        drop(imported);
        let source = [0x21; 32];
        let scheduler = crate::kagemusha_wallet_state_v1::Scheduler::new();
        scheduler.set_activity(true, false);
        let running = scheduler.start().unwrap();
        let cancellation = running.token.clone();
        let original = Original { proof, instances };
        let bytes = encode(
            &metadata,
            &params,
            0,
            source,
            &original,
            MemoryBudget::DEFAULT,
            &cancellation,
        )
        .unwrap();
        let restored = restore(
            &metadata,
            &params,
            0,
            source,
            &bytes,
            &original.instances,
            MemoryBudget::DEFAULT,
            &cancellation,
        )
        .unwrap();
        assert_eq!(restored.proof, original.proof);
        assert_eq!(restored.instances, original.instances);
        let foreign = PinnedParams::<Ep>::derive(7).unwrap();
        assert!(
            restore(
                &metadata,
                &foreign,
                0,
                source,
                &bytes,
                &original.instances,
                MemoryBudget::DEFAULT,
                &cancellation
            )
            .is_err()
        );
        assert!(
            restore(
                &metadata,
                &params,
                0,
                [0x22; 32],
                &bytes,
                &original.instances,
                MemoryBudget::DEFAULT,
                &cancellation
            )
            .is_err()
        );
        assert!(
            restore(
                &metadata,
                &params,
                0,
                source,
                &bytes,
                &[vec![Fq::from(2)]],
                MemoryBudget::DEFAULT,
                &cancellation
            )
            .is_err()
        );
        let mut changed = Layout::new(0, &metadata)
            .unwrap()
            .decode(&bytes, source)
            .unwrap();
        *changed.proof.last_mut().unwrap() ^= 1;
        let changed = norito::encode_canonical(&changed).unwrap();
        assert!(
            restore(
                &metadata,
                &params,
                0,
                source,
                &changed,
                &original.instances,
                MemoryBudget::DEFAULT,
                &cancellation
            )
            .is_err()
        );
        scheduler.set_activity(false, false);
        assert!(matches!(
            restore(
                &metadata,
                &params,
                0,
                source,
                &bytes,
                &original.instances,
                MemoryBudget::DEFAULT,
                &cancellation
            ),
            Err(Error::Cancelled)
        ));
        drop(running);
        scheduler.set_activity(true, false);
        let retry_running = scheduler.start().unwrap();
        let retry = restore(
            &metadata,
            &params,
            0,
            source,
            &bytes,
            &original.instances,
            MemoryBudget::DEFAULT,
            &retry_running.token,
        )
        .unwrap();
        assert_eq!(retry.proof, original.proof);
    }

    fn specimen() -> (Layout, Payload) {
        // Grammar-only unadmitted data; never accepted as a proof or key.
        let payload = Payload {
            version: 1,
            stage: 2,
            descriptor: [1; 32],
            key: [2; 32],
            source: [3; 32],
            proof: vec![4; 64],
            instances: vec![vec![[5; 32]; 3], vec![[6; 32]; 2]],
        };
        let bytes = norito::canonical_frame_len(&payload).unwrap();
        let layout = Layout {
            custody: super::super::layout(&[1; 32], &[2; 32], 1, 2, bytes).unwrap(),
            stage: 2,
            descriptor: [1; 32],
            key: [2; 32],
            proof_bytes: 64,
            columns: vec![3, 2],
        };
        (layout, payload)
    }
    #[test]
    fn bounded_q_carrier_rejects_source_key_order_shape_and_trailing_bytes() {
        let (layout, payload) = specimen();
        let bytes = norito::encode_canonical(&payload).unwrap();
        assert_eq!(layout.decode(&bytes, [3; 32]).unwrap().proof, payload.proof);
        assert!(layout.decode(&bytes, [4; 32]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(layout.decode(&trailing, [3; 32]).is_err());
        assert!(layout.decode(&bytes[..bytes.len() - 1], [3; 32]).is_err());
        for change in 0..8 {
            let (layout, mut payload) = specimen();
            match change {
                0 => payload.version = 2,
                1 => payload.stage += 1,
                2 => payload.descriptor[0] ^= 1,
                3 => payload.key[0] ^= 1,
                4 => payload.source[0] ^= 1,
                5 => {
                    payload.proof.pop();
                }
                6 => {
                    payload.instances.pop();
                }
                _ => {
                    payload.instances[0].pop();
                }
            }
            assert!(
                layout
                    .decode(&norito::encode_canonical(&payload).unwrap(), [3; 32])
                    .is_err()
            );
        }
    }
}
