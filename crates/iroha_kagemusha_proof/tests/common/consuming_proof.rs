//! Exact consuming-proof tape binding against a genuine hard predecessor proof.
//! The leaf is Load only to reuse an existing real proof; this tests the byte
//! component, not Send's operation or complete lineage authorization.

use super::*;
use iroha_kagemusha_proof::a_relation::own::ConsumingProofCells;
use iroha_plonk_gadgets::bytes::{chunk_segments, p_bytes_native};

#[derive(Clone)]
struct TapeBinding {
    first: First,
    corrupt: Option<(bool, usize)>,
}
impl TapeBinding {
    fn tapes(&self) -> [Vec<u8>; 2] {
        let source = &self.first.source;
        let f = source.maps.witness.predecessor.lineage;
        let mut omega = 1u16.to_le_bytes().to_vec();
        for i in [1, 2, 3, 4] {
            omega.extend(&f[i].to_repr()[..16]);
        }
        omega.extend(f[5].to_repr());
        for i in [6, 7] {
            omega.extend(&f[i].to_repr()[..16]);
        }
        omega.extend(f[8].to_repr());
        omega.push(4);
        for i in [10, 9, 12, 11] {
            omega.extend(f[i].to_repr()[..16].iter().rev());
        }
        let packed = f[13].to_repr();
        omega.extend(&packed[..13]);
        omega.extend(&f[14].to_repr()[..16]);
        omega.extend(f[15].to_repr());
        omega.extend(f[16].to_repr());
        assert_eq!(omega.len(), 320);
        omega.extend(&source.predecessor.proof);
        omega.extend(source.predecessor.pallas.to_bytes());
        omega.extend(source.predecessor.vesta.to_bytes());
        let frame = |body: &[u8]| {
            let mut out = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
            out.extend(body);
            out
        };
        let mut tapes = [frame(&omega), frame(&source.sigma)];
        if let Some((sigma, offset)) = self.corrupt {
            tapes[usize::from(sigma)][offset] ^= 1;
        }
        tapes
    }
    fn public(&self) -> Vec<Vec<Fp>> {
        let original = Self {
            corrupt: None,
            ..self.clone()
        }
        .tapes()
        .concat();
        vec![vec![p_bytes_native(
            u64::from_le_bytes(*b"kgwprf_1"),
            &original,
        )]]
    }
}
impl Circuit<Fp> for TapeBinding {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            first: self.first.without_witnesses(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign(meta, 4).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let first = &self.first;
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let digest = layouter.assign_region(
            || "real predecessor and exact consuming proof tape",
            |mut region| {
                let mut maps = first.source.maps.clone();
                maps.known = first.known;
                let (_, pred_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.predecessor)?;
                let (_, next_public) =
                    maps.state(&mut chip, &mut region, &maps.witness.successor)?;
                let fields = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &maps.witness.statement.map(|v| first.value(v)))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    Variant::Load,
                    &fields,
                )?;
                let sigma = first.sigma(&mut chip, &mut bytes, &mut region, &statement)?;
                let p = first.pallas(
                    &mut chip,
                    &mut region,
                    &first.source.predecessor.pallas.as_input(),
                )?;
                let v = first.vesta(&mut chip, &mut region, &first.source.predecessor.vesta)?;
                let key = chip.constant_key(
                    &mut region,
                    &first.source.predecessor.program,
                    &first.source.predecessor.key,
                )?;
                let proof = first.carrier(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    &first.source.predecessor.proof,
                )?;
                let predecessor = verify_predecessor(
                    &mut chip,
                    &mut region,
                    first.plan.operation(),
                    &key,
                    &pred_public,
                    &next_public,
                    &p,
                    &v,
                    &proof,
                )?;
                let [omega, sigma_tape] = self.tapes();
                let secondary =
                    ConsumingProofCells::omega_segments(first.source.predecessor.proof.len())?;
                let omega_run = bytes.run(
                    &mut region,
                    &omega.iter().map(|b| first.value(*b)).collect::<Vec<_>>(),
                    &chunk_segments(0, omega.len()),
                    &secondary,
                )?;
                let sigma_run = bytes.run(
                    &mut region,
                    &sigma_tape
                        .iter()
                        .map(|b| first.value(*b))
                        .collect::<Vec<_>>(),
                    &chunk_segments(0, sigma_tape.len()),
                    &[SegmentSpec::little(0, 4)],
                )?;
                let bound = ConsumingProofCells::from_runs(
                    &mut chip,
                    &mut region,
                    &predecessor,
                    &sigma,
                    &omega_run,
                    &sigma_run,
                )?;
                Ok(bound.digest().clone())
            },
        )?;
        layouter.constrain_instance(digest.cell(), config.public, 0)
    }
}
#[allow(clippy::redundant_pub_crate)] // Shared include retains a parent-private fixture type.
pub(super) fn check(first: &First) {
    let circuit = TapeBinding {
        first: first.clone(),
        corrupt: None,
    };
    let public = circuit.public();
    let report =
        iroha_plonk::check::check_circuit(&circuit, 16, &public, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{report:?}");
    let known = synthesize(&circuit, 16, None).unwrap();
    let unknown = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    let proof_end = 4 + 320 + first.source.predecessor.proof.len();
    for (sigma, offset) in [
        (false, 0),
        (false, 4),
        (false, 6),
        (false, 38),
        (false, 70),
        (false, 102),
        (false, 134),
        (false, 166),
        (false, 167),
        (false, 231),
        (false, 232),
        (false, 240),
        (false, 244),
        (false, 260),
        (false, 292),
        (false, 324),
        (false, proof_end - 1),
        (false, proof_end),
        (false, proof_end + 32),
        (false, proof_end + 544),
        (false, proof_end + 576),
        (false, proof_end + 1087),
        (true, 0),
        (true, 4),
        (true, first.source.sigma.len() + 3),
    ] {
        let bad = TapeBinding {
            corrupt: Some((sigma, offset)),
            ..circuit.clone()
        };
        assert!(
            !iroha_plonk::check::check_circuit(&bad, 16, &public, CheckMode::Strict)
                .is_ok_and(|r| r.is_satisfied()),
            "consuming tape mutation sigma={sigma} byte={offset}"
        );
    }
    let mut wrong_digest = public;
    wrong_digest[0][0] += Fp::ONE;
    assert!(
        !iroha_plonk::check::check_circuit(&circuit, 16, &wrong_digest, CheckMode::Strict)
            .unwrap()
            .is_satisfied()
    );
    eprintln!(
        "genuine predecessor transport + sigma P_bytes native parity and all carrier sections PASS"
    );
}
