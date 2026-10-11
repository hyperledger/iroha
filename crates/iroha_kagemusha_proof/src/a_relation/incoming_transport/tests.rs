//! Fixed-view carrier integration; these tests do not qualify variable ingestion.

mod verification;

use super::*;
use crate::{
    a_relation::context::{ContextObjectCells, ContextObjectSpec},
    operation_relation::incoming_statement::IncomingStatementCells,
};
use ff::{Field, PrimeField};
use iroha_pasta::{Eq, Fq, PastaAffine};
use iroha_plonk::{
    DescriptorBinding,
    check::{CheckMode, check_circuit},
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, Column, ConstraintSystem, CurveV1,
        DescriptorConfig, Instance, InstanceModeV1, InstanceType, ProofSuffixV1, TranscriptV1,
        TranscriptV2,
    },
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
    pcs::ipa::PinnedParams,
    transcript::decode_point,
};
use iroha_plonk_gadgets::{
    UintChip,
    bytes::{
        chunk_segments, p_bytes_native,
        tape::{BytesChip, BytesConfig},
    },
    statement::foreign_limbs,
};
use iroha_plonk_recursion::{
    AccumulatorT, PALLAS_TRIVIAL_GENERATOR, VESTA_TRIVIAL_GENERATOR, obligation::ledger::Variant,
    verifier::VerifierConfig,
};

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}

#[derive(Clone)]
struct Carrier {
    plan: IncomingTransportPlan,
    omega: Vec<u8>,
    sigma: [u8; 36],
    active: Option<(Vec<u8>, Vec<u8>)>,
    capacities: Option<(usize, usize)>,
    known: bool,
}

/// Decoder metadata only, shared by same-tape object composition tests.
pub(in crate::a_relation) fn decoder_fixture() -> (IncomingTransportPlan, Vec<u8>) {
    let fixture = Carrier::new();
    (fixture.plan, fixture.omega[4..].to_vec())
}

impl Circuit<Fp> for Carrier {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = usize;
    fn params(&self) -> usize {
        usize::from(self.capacities.is_some()) * 4
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, buses: usize) -> Config {
        Self::configure_profile(meta, buses)
    }

    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        Self::configure_profile(meta, 0)
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "same fixed carrier",
            |mut region| {
                let key = chip.uint().glue().constant(&mut region, Fp::from(41))?;
                let decoded = if let Some((omega, _)) = &self.active {
                    let raw = if self.known {
                        Value::known(omega.clone())
                    } else {
                        Value::unknown()
                    };
                    let active = ActiveBytes::assign(
                        &mut chip.uint(),
                        &mut bytes,
                        &mut region,
                        self.capacities
                            .map_or(self.plan.payload_length()? + 64, |caps| caps.0),
                        &raw,
                        &self.plan.active_segments()?,
                    )?;
                    self.plan
                        .decode_active(&mut chip, &mut region, &active, &key)?
                } else {
                    let values = self
                        .omega
                        .iter()
                        .map(|b| self.value(*b))
                        .collect::<Vec<_>>();
                    let run = bytes.run(
                        &mut region,
                        &values,
                        &chunk_segments(0, values.len()),
                        &ConsumingProofCells::omega_segments(self.plan.omega.proof_length())?,
                    )?;
                    self.plan.decode(&mut chip, &mut region, &run, &key)?
                };
                assert_eq!(decoded.pallas().source().original_k(), Some(16));
                assert_eq!(decoded.vesta().source_k(), 16);
                let mut output = decoded.public().fields().to_vec();
                output.extend([
                    decoded.public().valid().word().clone(),
                    decoded.decode_bits[0].word().clone(),
                    decoded.decode_bits[1].word().clone(),
                    decoded.pallas().g().x().clone(),
                    decoded.pallas().g().y().clone(),
                ]);
                for challenge in decoded.pallas().challenges() {
                    output.extend([challenge.lo().word().clone(), challenge.hi().word().clone()]);
                }
                output.extend(decoded.vesta().words());
                // Export the actual proof view too: a digest-only test would not
                // detect a misplaced embedded proof slice.
                for message in decoded.proof().messages() {
                    output.extend([
                        message.lo().word().clone(),
                        message.hi().word().clone(),
                        message.top().word().clone(),
                    ]);
                }
                let lanes = chip.operation_lanes()?;
                let fields = lanes
                    .glue
                    .witnesses(&mut region, &[self.value(Fp::ZERO); 26])?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = IncomingStatementCells::constrain(
                    &mut UintChip::new(lanes.glue, lanes.range),
                    lanes.hash,
                    &mut region,
                    Variant::Send,
                    &fields,
                )?;
                let index = chip.uint().glue().constant(&mut region, Fp::from(2))?;
                let (binding, digest) = if let Some((_, sigma)) = &self.active {
                    let raw = if self.known {
                        Value::known(sigma.clone())
                    } else {
                        Value::unknown()
                    };
                    let active = ActiveBytes::assign(
                        &mut chip.uint(),
                        &mut bytes,
                        &mut region,
                        self.capacities.map_or(64, |caps| caps.1),
                        &raw,
                        &SigmaBindingCells::incoming_segments(32)?,
                    )?;
                    let binding = SigmaBindingCells::from_incoming_active(
                        &mut chip,
                        &mut region,
                        &statement,
                        index,
                        &active,
                        32,
                    )?;
                    let digest = decoded.proof_digest(&mut chip, &mut region, &binding)?;
                    (binding, digest)
                } else {
                    let sigma = bytes.run(
                        &mut region,
                        &self.sigma.map(|b| self.value(b)),
                        &chunk_segments(0, 36),
                        &[SegmentSpec::little(0, 4)],
                    )?;
                    let binding = SigmaBindingCells::from_incoming_run(
                        &mut chip,
                        &mut region,
                        &statement,
                        index,
                        &sigma,
                    )?;
                    assert!(decoded.active_carrier().is_err());
                    assert!(binding.active_carrier().is_err());
                    assert!(
                        decoded
                            .proof_digest(&mut chip, &mut region, &binding)
                            .is_err()
                    );
                    let digest =
                        decoded.fixed_buffer_digest(&mut chip, &mut region, &binding, &sigma)?;
                    (binding, digest)
                };
                output.push(binding.step_digest()?.clone());
                output.push(digest);
                output.extend(binding.proof_chunks().iter().cloned());
                if self.active.is_some() {
                    let raw = decoded.active_carrier()?;
                    let context = ContextObjectCells::from_active(
                        &mut chip,
                        &mut region,
                        ContextObjectSpec {
                            tag: 91,
                            capacity: u32::try_from(raw.run().len()).unwrap(),
                        },
                        output
                            .get(output.len() - binding.proof_chunks().len() - 1)
                            .ok_or(Error::Synthesis)?,
                        raw,
                    )?;
                    output.extend(context.commitment_words());
                }

                let zero = chip.uint().glue().constant(&mut region, Fp::ZERO)?;
                if output.len() > 256 {
                    return Err(Error::BoundsFailure);
                }
                output.resize(256, zero);
                Ok(output)
            },
        )?;
        for (row, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}

impl Carrier {
    fn configure_profile(meta: &mut ConstraintSystem<Fp>, buses: usize) -> Config {
        let verifier = if buses == 0 {
            VerifierConfig::configure(meta)
        } else {
            VerifierConfig::configure_serialized_foreign(meta, buses).unwrap()
        };
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(256);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn value<T: Copy>(&self, value: T) -> Value<T> {
        if self.known {
            Value::known(value)
        } else {
            Value::unknown()
        }
    }
    fn new() -> Self {
        // This empty descriptor is decoder metadata only, never an Omega proof.
        let mut cs = ConstraintSystem::<Fq>::default();
        for count in [1, 2, 16] {
            cs.instance_column(count);
        }
        let layout = CircuitDescriptorV1::from_constraint_system(
            &cs.finalize(&[], false).unwrap(),
            DescriptorConfig {
                curve: CurveV1::Pallas,
                k: 16,
                transcript: TranscriptV1::KagemushaPoseidonRp57,
                instance_mode: InstanceModeV1::Direct,
                proof_suffix: ProofSuffixV1::FoldedGenerator,
            },
        )
        .unwrap();
        let descriptor = CircuitDescriptorV2::from_layout(
            layout,
            TranscriptV2::KagemushaPoseidonRp57Base,
            vec![
                InstanceType::Bounded,
                InstanceType::Field,
                InstanceType::Bounded,
            ],
        )
        .unwrap();
        let params = PinnedParams::<Ep>::derive(16).unwrap();
        let plan = IncomingTransportPlan {
            omega: VerifierPlan::new(
                DescriptorBinding::new_v2(descriptor).unwrap(),
                params.clone(),
            )
            .unwrap(),
            pallas: FoldInputDecodePlan::new(&params, 16).unwrap(),
        };
        let mut omega = vec![0; plan.payload_length().unwrap() + 4];
        let length = u32::try_from(omega.len() - 4).unwrap();
        omega[..4].copy_from_slice(&length.to_le_bytes());
        omega[4..6].copy_from_slice(&1_u16.to_le_bytes());
        omega[4 + 162] = 4;
        for (i, byte) in omega[324..324 + plan.omega.proof_length()]
            .iter_mut()
            .enumerate()
        {
            *byte = u8::try_from(i % 251).unwrap();
        }
        let p = AccumulatorT::<Ep>::new(
            decode_point::<Ep>(&PALLAS_TRIVIAL_GENERATOR).unwrap(),
            [Fq::from(3); 16],
        )
        .unwrap();
        let v = AccumulatorT::<Eq>::new(
            decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap(),
            [Fp::from(5); 16],
        )
        .unwrap();
        let start = 324 + plan.omega.proof_length();
        omega[start..start + 544].copy_from_slice(&p.to_bytes());
        omega[start + 544..].copy_from_slice(&v.to_bytes());
        let mut sigma = [17; 36];
        sigma[..4].copy_from_slice(&32_u32.to_le_bytes());
        Self {
            plan,
            omega,
            sigma,
            active: None,
            capacities: None,
            known: true,
        }
    }
    fn instances(&self) -> Vec<Vec<Fp>> {
        if let Some((omega, sigma)) = &self.active {
            let mut fixed = self.clone();
            fixed.active = None;
            fixed.omega.fill(0);
            fixed.omega[..4].copy_from_slice(&u32::try_from(omega.len()).unwrap().to_le_bytes());
            let count = omega.len().min(fixed.omega.len() - 4);
            fixed.omega[4..4 + count].copy_from_slice(&omega[..count]);
            fixed.sigma.fill(0);
            fixed.sigma[..4].copy_from_slice(&u32::try_from(sigma.len()).unwrap().to_le_bytes());
            let count = sigma.len().min(32);
            fixed.sigma[4..4 + count].copy_from_slice(&sigma[..count]);
            let mut expected = fixed.instances();
            let digest_offset = 75 + 3 * self.plan.omega.proof_length() / 32;
            let framed = |raw: &[u8]| {
                let mut out = u32::try_from(raw.len()).unwrap().to_le_bytes().to_vec();
                out.extend(raw);
                out
            };
            expected[0][digest_offset] =
                p_bytes_native(u64::from_le_bytes(*b"kgwstep1"), &framed(sigma));
            expected[0][digest_offset + 1] = p_bytes_native(
                u64::from_le_bytes(*b"kgwprf_1"),
                &[framed(omega), framed(sigma)].concat(),
            );
            let context = digest_offset + 2 + 36_usize.div_ceil(31);
            let length = Fp::from(u64::try_from(omega.len()).unwrap());
            let capacity = self
                .capacities
                .map_or_else(|| self.plan.payload_length().unwrap() + 64, |caps| caps.0);
            let original = p_bytes_native(u64::from_le_bytes(*b"kgwcact1"), &framed(omega));
            expected[0][context] = expected[0][digest_offset + 1];
            expected[0][context + 1] = length;
            expected[0][context + 2] = iroha_pasta::poseidon::hash_with_domain(
                u64::from_le_bytes(*b"kgwcact1"),
                &[
                    Fp::from(91),
                    Fp::from(u64::try_from(capacity).unwrap()),
                    length,
                    original,
                ],
            );
            return expected;
        }
        let proof_end = 324 + self.plan.omega.proof_length();
        let p = AccumulatorT::<Ep>::from_bytes(&self.omega[proof_end..proof_end + 544]);
        let v = AccumulatorT::<Eq>::from_bytes(&self.omega[proof_end + 544..]);
        let p_valid = p.is_ok();
        let v_valid = v.is_ok();
        let p = p.unwrap_or_else(|_| {
            AccumulatorT::<Ep>::new(
                decode_point::<Ep>(&PALLAS_TRIVIAL_GENERATOR).unwrap(),
                [Fq::ONE; 16],
            )
            .unwrap()
        });
        let v = v.unwrap_or_else(|_| {
            AccumulatorT::<Eq>::new(
                decode_point::<Eq>(&VESTA_TRIVIAL_GENERATOR).unwrap(),
                [Fp::ONE; 16],
            )
            .unwrap()
        });
        let mut output = vec![Fp::ZERO; 18];
        output[0] = Fp::from(u64::from(u16::from_le_bytes(
            self.omega[4..6].try_into().unwrap(),
        )));
        output[17] = Fp::from(41);
        output.extend([
            Fp::from(u64::from(
                u32::from_le_bytes(self.omega[..4].try_into().unwrap()) as usize
                    == self.omega.len() - 4
                    && self.omega[4..6] == 1_u16.to_le_bytes()
                    && self.omega[166] == 4,
            )),
            Fp::from(u64::from(p_valid)),
            Fp::from(u64::from(v_valid)),
        ]);
        let (x, y) = Option::from(p.g().coordinates()).unwrap();
        output.extend([x, y]);
        for challenge in p.challenges() {
            output.extend(foreign_limbs(challenge).map(Fp::from_u128));
        }
        let (x, y) = Option::from(v.g().coordinates()).unwrap();
        for coordinate in [x, y] {
            output.extend(foreign_limbs(&coordinate).map(Fp::from_u128));
        }
        output.extend(v.challenges());
        for message in self.omega[324..proof_end].chunks_exact(32) {
            let lo = u128::from_le_bytes(message[..16].try_into().unwrap());
            let mut high: [u8; 16] = message[16..].try_into().unwrap();
            let top = high[15] >> 7;
            high[15] &= 127;
            output.extend([
                Fp::from_u128(lo),
                Fp::from_u128(u128::from_le_bytes(high)),
                Fp::from(u64::from(top)),
            ]);
        }
        output.push(p_bytes_native(
            u64::from_le_bytes(*b"kgwstep1"),
            &self.sigma,
        ));
        let mut all = self.omega.clone();
        all.extend(self.sigma);
        output.push(p_bytes_native(u64::from_le_bytes(*b"kgwprf_1"), &all));
        output.extend(self.sigma.chunks(31).map(|chunk| {
            let mut repr = [0; 32];
            repr[..chunk.len()].copy_from_slice(chunk);
            Fp::from_repr(repr).unwrap()
        }));
        assert!(output.len() <= 256);
        output.resize(256, Fp::ZERO);
        vec![output]
    }
}

#[test]
fn fixed_carrier_preserves_slices_and_soft_claim_failures() {
    let honest = Carrier::new();
    let start = 324 + honest.plan.omega.proof_length();
    let mut cases = vec![honest.clone()];
    for offset in [start, start + 32, start + 544, start + 544 + 32] {
        let mut bad = honest.clone();
        bad.omega[offset..offset + 32].fill(0);
        cases.push(bad);
    }
    let mut short = honest.clone();
    short.omega[..4].copy_from_slice(&1_u32.to_le_bytes());
    cases.push(short);
    let mut sigma_short = honest.clone();
    sigma_short.sigma[..4].copy_from_slice(&0_u32.to_le_bytes());
    cases.push(sigma_short);
    let mut proof_changed = honest.clone();
    proof_changed.omega[324] ^= 128;
    proof_changed.omega[start - 1] ^= 128;
    cases.push(proof_changed);
    for (index, circuit) in cases.iter().enumerate() {
        let public = circuit.instances();
        assert!(
            check_circuit(circuit, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "case {index}"
        );
        if index != 0 {
            assert!(
                !check_circuit(circuit, 16, &honest.instances(), CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "substitution {index}"
            );
        }
        if (1..=4).contains(&index) {
            let mut forged = public;
            forged[0][19 + usize::from(index > 2)] = Fp::ONE;
            assert!(
                !check_circuit(circuit, 16, &forged, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "forged decoder bit {index}"
            );
        }
    }
    let known = synthesize(&honest, 16, None).unwrap();
    let unknown = synthesize(&honest.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    for bad in &cases[1..] {
        let layout = synthesize(bad, 16, None).unwrap();
        assert_eq!(known.tables.fixed(), layout.tables.fixed());
        assert_eq!(known.tables.permutation(), layout.tables.permutation());
    }
}

#[test]
fn active_original_lengths_and_tails_never_alias_padded_verifier_views() {
    let base = Carrier::new();
    let mut omega = base.omega[4..].to_vec();
    let mut sigma = base.sigma[4..].to_vec();
    sigma[31] = 0;
    assert_eq!(*omega.last().unwrap(), 0);
    let mut honest = base.clone();
    honest.active = Some((omega.clone(), sigma.clone()));
    let mut cases = vec![honest.clone()];
    for which in [0, 1] {
        for extra in [false, true] {
            let mut bad = honest.clone();
            let (omega, sigma) = bad.active.as_mut().unwrap();
            let target = if which == 0 { omega } else { sigma };
            if extra {
                target.push(0);
            } else {
                target.pop();
            }
            cases.push(bad);
        }
    }
    let mut tail = honest.clone();
    tail.active.as_mut().unwrap().1.push(7);
    cases.push(tail);
    let mut empty = honest.clone();
    empty.active = Some((Vec::new(), Vec::new()));
    cases.push(empty);
    let known = synthesize(&honest, 16, None).unwrap();
    let unknown = synthesize(&honest.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    let digest_offset = 75 + 3 * base.plan.omega.proof_length() / 32;
    for (index, case) in cases.iter().enumerate() {
        let expected = case.instances();
        let report = check_circuit(case, 16, &expected, CheckMode::Strict).unwrap();
        assert!(
            report.is_satisfied(),
            "case {index}: {:?}",
            report.failures().first()
        );
        if index != 0 {
            assert_ne!(
                expected[0][digest_offset + 1],
                honest.instances()[0][digest_offset + 1]
            );
            let mut forged = expected.clone();
            forged[0][digest_offset + 1] = honest.instances()[0][digest_offset + 1];
            assert!(
                !check_circuit(case, 16, &forged, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied()
            );
        }
        let shape = synthesize(case, 16, None).unwrap();
        assert_eq!(known.tables.fixed(), shape.tables.fixed());
        assert_eq!(known.tables.permutation(), shape.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            shape.tables.advice_assigned()
        );
    }
    // Appending a nonzero original tail must be bound too, even though Q's
    // fixed32-byte arithmetic view discards it and rejects the length.
    omega.push(0);
    sigma.push(9);
    let mut changed = honest;
    changed.active = Some((omega, sigma));
    let expected = changed.instances();
    assert!(
        check_circuit(&changed, 16, &expected, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
}

#[test]
#[ignore = "maximum independent raw capacities with full active decoder/hash/context on the A4 profile"]
fn active_raw_maximum_capacity_inventory() {
    let mut circuit = Carrier::new();
    circuit.capacities = Some((8132, 10000));
    circuit.active = Some((circuit.omega[4..].to_vec(), circuit.sigma[4..].to_vec()));
    let expected = circuit.instances();
    let report = check_circuit(&circuit, 16, &expected, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let assigned = synthesize(&circuit, 16, None).unwrap();
    let lanes = assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|lane| lane.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!(
        "ACTIVE_RAW_DECODER_PROOF_CONTEXT A4 maxcap8132+10000 lanes={lanes:?}; component_only=true whole_Payment_cap_still_required=true"
    );
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(assigned.tables.fixed(), unknown.tables.fixed());
    assert_eq!(assigned.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        assigned.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
}
