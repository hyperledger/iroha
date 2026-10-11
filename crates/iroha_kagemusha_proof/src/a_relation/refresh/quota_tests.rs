//! Exact private quota commitment binding across the fixed root/merge owners.

use super::*;
use crate::operation_relation::quota_refresh::QUOTA_WITNESS_WORDS;
use iroha_pasta::poseidon::hash_with_domain;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    frontend::synthesize,
};
use iroha_plonk_gadgets::bytes::tape::{BytesChip, BytesConfig};
use iroha_plonk_recursion::verifier::VerifierConfig;

#[derive(Clone)]
struct QuotaContext {
    originals: Originals,
    words: Vec<Fp>,
    proposed: [Fp; 5],
    task: OperationTask,
}
impl Circuit<Fp> for QuotaContext {
    type Config = OriginalConfig;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            originals: self.originals.without_witnesses(),
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        OriginalConfig {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let value = |v| {
            if self.originals.known {
                Value::known(v)
            } else {
                Value::unknown()
            }
        };
        let commitment = layouter.assign_region(
            || "quota original witness commitment",
            |mut r| {
                let tapes = self
                    .originals
                    .sources
                    .each_ref()
                    .map(|s| s.iter().map(|v| value(*v)).collect::<Vec<_>>());
                let fields = chip.uint().glue().witnesses(
                    &mut r,
                    &self.proposed.map(|v| {
                        if self.originals.known {
                            Value::known(v)
                        } else {
                            Value::unknown()
                        }
                    }),
                )?;
                let proposed = QuotaCommitmentCells {
                    previous_usage: fields[0].clone(),
                    windows: fields[1].clone(),
                    successor_usage: fields[2].clone(),
                    issued: fields[3].clone(),
                    window_count: fields[4].clone(),
                };
                let objects = RefreshObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut r,
                    Variant::RefreshQuotaShare,
                    tapes.each_ref().map(Vec::as_slice),
                )?
                .with_quota_commitment(&mut chip, &mut r, &proposed)?;
                let fields = chip.uint().glue().witnesses(
                    &mut r,
                    &self
                        .words
                        .iter()
                        .map(|v| {
                            if self.originals.known {
                                Value::known(*v)
                            } else {
                                Value::unknown()
                            }
                        })
                        .collect::<Vec<_>>(),
                )?;
                if fields.len() != QUOTA_WITNESS_WORDS {
                    return Err(Error::Synthesis);
                }
                let witness = QuotaRebuildCells {
                    old: core::array::from_fn(|i| {
                        core::array::from_fn(|j| fields[4 * i + j].clone())
                    }),
                    windows: core::array::from_fn(|i| {
                        core::array::from_fn(|j| fields[256 + 4 * i + j].clone())
                    }),
                    used: core::array::from_fn(|i| fields[512 + i].clone()),
                    issued: fields[576].clone(),
                    window_count: fields[577].clone(),
                };
                objects.bind_quota_witness(&mut chip, &mut r, &witness, self.task)?;
                Ok(objects.context()[5].authenticated_digest().clone())
            },
        )?;
        layouter.constrain_instance(commitment.cell(), config.public, 0)
    }
}
fn commitments(words: &[Fp]) -> [Fp; 5] {
    assert_eq!(words.len(), QUOTA_WITNESS_WORDS);
    let array = |tag, values: &[Fp]| {
        let mut framed = vec![
            Fp::from(tag),
            Fp::from(u64::try_from(values.len()).unwrap()),
        ];
        framed.extend_from_slice(values);
        hash_with_domain(u64::from_le_bytes(*b"kgwciw_1"), &framed)
    };
    [
        array(7, &words[..256]),
        array(8, &words[256..512]),
        array(9, &words[512..576]),
        words[576],
        words[577],
    ]
}
fn public(c: &QuotaContext) -> Vec<Vec<Fp>> {
    let mut framed = vec![Fp::from(6), Fp::from(5)];
    framed.extend(c.proposed);
    vec![vec![hash_with_domain(
        u64::from_le_bytes(*b"kgwciw_1"),
        &framed,
    )]]
}
fn fixture(task: OperationTask) -> QuotaContext {
    let words = (1..=QUOTA_WITNESS_WORDS)
        .map(|i| Fp::from(u64::try_from(i).unwrap()))
        .collect::<Vec<_>>();
    QuotaContext {
        originals: originals(Variant::RefreshQuotaShare),
        proposed: commitments(&words),
        words,
        task,
    }
}
#[test]
fn quota_owners_cannot_substitute_consumed_arrays_issue_count_or_commitments() {
    // Distinct words test commitment framing only. Separate root/semantic tests
    // require valid quota arrays; this does not prove a complete quota operation.
    for (task, indices) in [
        (
            OperationTask::RefreshQuotaPreviousRoot,
            &[0, 255, 576, 577][..],
        ),
        (
            OperationTask::RefreshQuotaWindowRoot,
            &[256, 511, 576, 577][..],
        ),
        (
            OperationTask::RefreshQuotaUsageRoot,
            &[256, 511, 512, 575, 576, 577][..],
        ),
        (
            OperationTask::RefreshQuotaMerge,
            &[0, 255, 256, 511, 512, 575, 576, 577][..],
        ),
    ] {
        let c = fixture(task);
        let public = public(&c);
        assert!(
            check_circuit(&c, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let known = synthesize(&c, 16, Some(&public)).unwrap();
        let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
        let rows = known
            .tables
            .advice_assigned()
            .iter()
            .map(|c| c.iter().rposition(|v| *v).map_or(0, |i| i + 1))
            .collect::<Vec<_>>();
        eprintln!(
            "QUOTA_TYPED_COMMITMENT task={task:?} rows={rows:?} includes_signed_original_decode=true includes_W=false"
        );
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        for &i in indices {
            let mut bad = c.clone();
            bad.words[i] += Fp::ONE;
            assert!(
                !check_circuit(&bad, 16, &public, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "{task:?} changed consumed quota word{i}"
            );
            bad.proposed = commitments(&bad.words);
            assert!(
                !check_circuit(&bad, 16, &public, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "{task:?} rehashed private array cannot replace prior context{i}"
            );
        }
        for i in 0..5 {
            let mut bad = c.clone();
            bad.proposed[i] += Fp::ONE;
            assert!(
                !check_circuit(&bad, 16, &public, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "{task:?} cannot replace context tuple element{i}"
            );
        }
        let mut swapped = c.clone();
        swapped.proposed.swap(0, 1);
        assert!(
            !check_circuit(&swapped, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        let mut short = c;
        short.words.pop();
        assert!(synthesize(&short, 16, Some(&public)).is_err());
    }
}
