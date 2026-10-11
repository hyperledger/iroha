//! Full native schedule equivalence and constrained start-state mutations.
use super::super::super::curve::{G1AffineWitness, G2AffineWitness};
use super::*;
use crate::{
    arith::{GlueChip, GlueConfig},
    bls12_381::extension::{Fp2Value, Fp6Value},
    range::{LimbBits, RunningSumChip, RunningSumConfig},
};
use ark_bls12_381::{Bls12_381, Config as BlsConfig, Fq, Fq2, Fq12, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, bls12::G2Prepared, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use core::marker::PhantomData;
use iroha_pasta::{Fp as PastaFp, Fq as PastaFq};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value},
};

fn native_miller(p: [G1Affine; 2], q: &[G2Affine; 2]) -> Fq12 {
    let prepared = q.map(G2Prepared::<BlsConfig>::from);
    let mut cursor = [0; 2];
    let mut points = *q;
    let mut lines = [(Fq2::ZERO, Fq2::ZERO, Fq2::ZERO); 2];
    let mut acc = Fq12::ONE;
    for step in MILLER_STEPS {
        match step {
            MillerStep::Square => acc.square_in_place(),
            MillerStep::Double { pair } => {
                points[pair] = (points[pair] + points[pair]).into_affine();
                lines[pair] = prepared[pair].ell_coeffs[cursor[pair]];
                cursor[pair] += 1;
                &mut acc
            }
            MillerStep::Add { pair } => {
                points[pair] = (points[pair] + q[pair]).into_affine();
                lines[pair] = prepared[pair].ell_coeffs[cursor[pair]];
                cursor[pair] += 1;
                &mut acc
            }
            MillerStep::Evaluate { pair } => {
                let c = lines[pair];
                acc.mul_by_014(
                    &c.0,
                    &(c.1 * Fq2::new(p[pair].x, Fq::ZERO)),
                    &(c.2 * Fq2::new(p[pair].y, Fq::ZERO)),
                );
                &mut acc
            }
            MillerStep::Conjugate => {
                acc = Fq12::new(acc.c0, -acc.c1);
                &mut acc
            }
        };
    }
    for pair in 0..2 {
        assert_eq!(cursor[pair], prepared[pair].ell_coeffs.len());
        assert_eq!(points[pair], q[pair].mul_bigint([MILLER_X]).into_affine());
    }
    acc
}
fn native_final(value: &Fq12) -> Fq12 {
    use super::super::final_exponent::{FINAL_EXPONENT_STEPS, FinalExponentStep as S};
    let mut r = [Fq12::ZERO; 5];
    r[0] = *value;
    for step in FINAL_EXPONENT_STEPS {
        match step {
            S::Copy {
                destination,
                source,
            } => r[destination] = r[source],
            S::Multiply {
                destination,
                left,
                right,
            } => r[destination] = r[left] * r[right],
            S::Square {
                destination,
                source,
            } => r[destination] = r[source].square(),
            S::Inverse {
                destination,
                source,
            } => r[destination] = r[source].inverse().unwrap(),
            S::Conjugate {
                destination,
                source,
            } => r[destination] = Fq12::new(r[source].c0, -r[source].c1),
            S::Frobenius {
                destination,
                source,
                power,
            } => r[destination] = r[source].frobenius_map(power),
        }
    }
    r[0]
}
#[test]
fn complete_miller_and_final_exponent_schedules_match_native_pairing() {
    let p = [
        G1Affine::generator().mul_bigint([17_u64]).into_affine(),
        -G1Affine::generator(),
    ];
    let message = G2Affine::generator().mul_bigint([23_u64]).into_affine();
    let signature = message.mul_bigint([17_u64]).into_affine();
    for (candidate, valid) in [
        (signature, true),
        ((signature + G2Affine::generator()).into_affine(), false),
    ] {
        let q = [message, candidate];
        let miller = native_miller(p, &q);
        assert_eq!(miller, Bls12_381::multi_miller_loop(p, q).0);
        let pairing = native_final(&miller);
        assert_eq!(pairing, Bls12_381::multi_pairing(p, q).0);
        assert_eq!(pairing == Fq12::ONE, valid);
    }
}
fn fp2(x: Fq2) -> super::super::super::extension::Fp2 {
    [x.c0.into_bigint().0, x.c1.into_bigint().0]
}
#[derive(Clone)]
struct StartCircuit<F: PastaField> {
    forgery: u8,
    known: bool,
    marker: PhantomData<F>,
}
impl<F: PastaField> StartCircuit<F> {
    fn witness<T: Copy>(&self, x: T) -> Value<T> {
        if self.known {
            Value::known(x)
        } else {
            Value::unknown()
        }
    }
    fn public(&self) -> Vec<F> {
        let mut out = vec![F::ZERO; 72];
        out[0] = F::from(if self.forgery == 1 { 4_u64 } else { 1 });
        out
    }
}
#[derive(Clone)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    instance: Column<Instance>,
}
impl<F: PastaField> Circuit<F> for StartCircuit<F> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, constants);
        let z = meta.advice_column();
        let range = RunningSumConfig::configure(meta, z, LimbBits::new(8).unwrap());
        let instance = meta.instance_column(72);
        meta.enable_equality(instance);
        Config {
            glue,
            range,
            instance,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        range.load_table(&mut layouter)?;
        let mut chip = Bls381Chip::new(&mut glue, &mut range);
        let out = layouter.assign_region(
            || "Miller fixed start",
            |mut region| {
                let p = G1Affine::generator();
                let p = chip.assign_g1(
                    &mut region,
                    self.witness(G1AffineWitness {
                        x: p.x.into_bigint().0,
                        y: p.y.into_bigint().0,
                        infinity: false,
                    }),
                )?;
                let q = G2Affine::generator();
                let q = chip.assign_g2(
                    &mut region,
                    self.witness(G2AffineWitness {
                        x: fp2(q.x),
                        y: fp2(q.y),
                        infinity: false,
                    }),
                )?;
                let point = if self.forgery == 3 {
                    let p = chip.add_g2(&mut region, &q, &q)?;
                    chip.start_miller_g2(&mut region, &p)?
                } else {
                    chip.start_miller_g2(&mut region, &q)?
                };
                let mut raw_line = [[native::ZERO; 2]; 3];
                if self.forgery == 2 {
                    raw_line[0][0] = native::ONE;
                }
                let line = chip.assign_miller_line(&mut region, &self.witness(raw_line))?;
                let mut raw_acc = [[[native::ZERO; 2]; 3]; 2];
                raw_acc[0][0][0] = [if self.forgery == 1 { 2 } else { 1 }, 0, 0, 0, 0, 0];
                let acc = chip.assign_fp12(&mut region, &self.witness(raw_acc))?;
                let state =
                    MillerPairState::from_parts([point.clone(), point], [line.clone(), line], acc);
                let result = chip.miller_pair_step(
                    &mut region,
                    &state,
                    &[p.clone(), p],
                    &[q.clone(), q],
                    0,
                )?;
                Ok(result
                    .accumulator()
                    .coefficients()
                    .iter()
                    .flat_map(Fp6Value::coefficients)
                    .flat_map(Fp2Value::coefficients)
                    .flat_map(|x| x.limbs().iter().cloned())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.instance, i)?;
        }
        Ok(())
    }
}
fn starts<F: PastaField>() {
    for forgery in 0..4 {
        let c = StartCircuit::<F> {
            forgery,
            known: true,
            marker: PhantomData,
        };
        assert_eq!(
            check_circuit(&c, 17, &[c.public()], CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            forgery == 0,
            "forgery {forgery}"
        );
    }
}
#[test]
fn fixed_start_rejects_consistent_accumulator_line_and_point_forgery() {
    starts::<PastaFp>();
    starts::<PastaFq>();
}

#[test]
fn ordinary_iroha_bls_signatures_match_exact_w3f_hash_and_full_pairing_schedule() {
    use ark_bls12_381::{G2Projective, g2};
    use ark_ec::hashing::{
        HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher,
    };
    use ark_ff::field_hashers::DefaultFieldHasher;
    use ark_serialize::CanonicalDeserialize;
    use iroha_crypto::{Algorithm, KeyPair, PrivateKey, Signature};
    use sha2::Sha256;
    type Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>;
    let mut secret = [0_u8; 32];
    secret[0] = 17;
    let key =
        KeyPair::from_private_key(PrivateKey::from_bytes(Algorithm::BlsNormal, &secret).unwrap())
            .unwrap();
    let public = G1Affine::deserialize_compressed(key.public_key().to_bytes().1).unwrap();
    assert_eq!(
        public,
        G1Affine::generator().mul_bigint([17_u64]).into_affine()
    );
    let hasher = Hasher::new(&[1]).unwrap();
    for message in [
        b"".as_slice(),
        b"ordinary Sumeragi CommitQC",
        &[0x53_u8; 165],
    ] {
        let signature = Signature::new(key.private_key(), message);
        assert!(signature.verify(key.public_key(), message).is_ok());
        let signature_point = G2Affine::deserialize_compressed(signature.payload()).unwrap();
        let mut exact = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_for signing messages".to_vec();
        exact.extend_from_slice(message);
        let hash = hasher.hash(&exact).unwrap();
        assert_eq!(
            signature_point,
            hash.mul_bigint([17_u64]).into_affine(),
            "exact native W3f prefix, domain and mapping"
        );
        let p = [public, -G1Affine::generator()];
        assert_eq!(
            native_final(&native_miller(p, &[hash, signature_point])),
            Fq12::ONE
        );
        let mut changed = exact;
        changed.push(0);
        let wrong_hash = hasher.hash(&changed).unwrap();
        assert_ne!(
            native_final(&native_miller(p, &[wrong_hash, signature_point])),
            Fq12::ONE
        );
        // The IETF/Ethereum ciphersuite-as-DST convention hashes a different point.
        let other = Hasher::new(b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
            .unwrap()
            .hash(message)
            .unwrap();
        assert_ne!(hash, other);
    }
}
