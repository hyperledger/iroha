//! Total Request pair selection and depth32 authenticated history predicates.

use super::*;
use crate::{
    operation_relation::{
        map_effects::BLACKLIST_HISTORY_DOMAIN,
        objects::{ObjectKind, SignedObjectCells},
        state::{StateCells, rest_index},
    },
    witness::core_index,
};
use ff::PrimeField;
use iroha_pasta::poseidon::hash_with_domain;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    bytes::tape::{BytesChip, BytesConfig},
    imt::{LEAF_DOMAIN, LeafCells, NODE_DOMAIN, PathCells},
};
use iroha_plonk_recursion::verifier::VerifierConfig;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
#[derive(Clone)]
struct History {
    request: Vec<u8>,
    root: Fp,
    opening: [Fp; 36],
    valid: bool,
    selector: u64,
    known: bool,
}
impl Circuit<Fp> for History {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign(meta, 4).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(2);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "total recorded Request pair",
            |mut region| {
                let value = |x| {
                    if self.known {
                        Value::known(x)
                    } else {
                        Value::unknown()
                    }
                };
                let source = self
                    .request
                    .iter()
                    .map(|b| {
                        if self.known {
                            Value::known(*b)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect::<Vec<_>>();
                let run = bytes.run(
                    &mut region,
                    &source,
                    &ObjectKind::Request.primary_segments(),
                    &ObjectKind::Request.secondary_segments(),
                )?;
                let lanes = chip.operation_lanes()?;
                let object = SignedObjectCells::decode_soft(
                    &mut UintChip::new(lanes.glue, lanes.range),
                    lanes.hash,
                    &mut region,
                    ObjectKind::Request,
                    &run,
                )?
                .0;
                let mut core = [Fp::ZERO; 33];
                core[core_index::LIFECYCLE] = Fp::ONE;
                for (index, field) in core.iter_mut().enumerate().take(8).skip(1) {
                    *field = Fp::from(u64::try_from(index).unwrap());
                }
                for (index, field) in core.iter_mut().enumerate().take(21).skip(16) {
                    *field = Fp::from(u64::try_from(index).unwrap());
                }
                core[core_index::STATE_NONCE] = Fp::from(77);
                // Current held policy is deliberately unrelated to either
                // recorded history entry and must never replace the Request.
                core[core_index::BLACKLIST_VERSION] = Fp::from(9);
                core[core_index::BLACKLIST_ROOT] = Fp::from(91);
                let mut rest = [Fp::ZERO; 8];
                rest[rest_index::BLACKLIST] = Fp::from(95);
                rest[rest_index::BLACKLIST_HISTORY] = self.root;
                let core = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &core.map(value))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let rest = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &rest.map(value))?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let state =
                    StateCells::constrain_with_verifier(&mut chip, &mut region, &core, &rest)?;
                let opening = chip
                    .uint()
                    .glue()
                    .witnesses(&mut region, &self.opening.map(value))?;
                let opening = OpeningCells {
                    leaf: LeafCells::from_words(core::array::from_fn(|i| opening[i].clone())),
                    path: PathCells::from_words(
                        &mut chip.uint(),
                        &mut region,
                        &opening[3],
                        core::array::from_fn(|i| opening[4 + i].clone()),
                    )?,
                };
                let (valid, selector) =
                    blacklist_result(&mut chip, &mut region, &object, &state, &opening)?;
                Ok([valid.word().clone(), selector])
            },
        )?;
        for (row, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, row)?;
        }
        Ok(())
    }
}
impl History {
    fn new(version: u64, root: u64, route: u32) -> Self {
        let leaves = BTreeMap::from([
            (0, [Fp::ZERO, Fp::ZERO, Fp::ONE]),
            (
                1,
                [
                    Fp::ONE,
                    hash_with_domain(BLACKLIST_HISTORY_DOMAIN, &[Fp::ONE, Fp::from(81)]),
                    Fp::from(2),
                ],
            ),
            (
                2,
                [
                    Fp::from(2),
                    hash_with_domain(BLACKLIST_HISTORY_DOMAIN, &[Fp::from(2), Fp::from(82)]),
                    Fp::ZERO,
                ],
            ),
        ]);
        let mut nodes = leaves
            .iter()
            .map(|(i, leaf)| (*i, hash_with_domain(LEAF_DOMAIN, leaf)))
            .collect::<BTreeMap<_, _>>();
        let mut empty = Fp::ZERO;
        let mut opening = leaves[&route].to_vec();
        opening.push(Fp::from(u64::from(route)));
        for height in 0..32 {
            opening.push(
                nodes
                    .get(&((route >> height) ^ 1))
                    .copied()
                    .unwrap_or(empty),
            );
            let mut next = BTreeMap::new();
            for i in nodes.keys() {
                let pair = [
                    nodes.get(&(i & !1)).copied().unwrap_or(empty),
                    nodes.get(&(i | 1)).copied().unwrap_or(empty),
                ];
                next.insert(i >> 1, hash_with_domain(NODE_DOMAIN, &pair));
            }
            empty = hash_with_domain(NODE_DOMAIN, &[empty; 2]);
            nodes = next;
        }
        let mut request = vec![0; ObjectKind::Request.body_len() + 64];
        request[..2].copy_from_slice(&1_u16.to_le_bytes());
        request[306..314].copy_from_slice(&7_u64.to_le_bytes()); // unrelated policy epoch
        request[314..346].copy_from_slice(&Fp::from(99).to_repr()); // unrelated policy digest
        request[354..362].copy_from_slice(&version.to_le_bytes());
        request[362..394].copy_from_slice(&Fp::from(root).to_repr());
        Self {
            request,
            root: nodes[&0],
            opening: opening.try_into().unwrap(),
            valid: matches!((version, root), (0, 0) | (1, 81) | (2, 82)),
            selector: 10 + u64::from(version != 0),
            known: true,
        }
    }
    fn accepts(&self) -> bool {
        check_circuit(
            self,
            16,
            &[vec![
                Fp::from(u64::from(self.valid)),
                Fp::from(self.selector),
            ]],
            CheckMode::Strict,
        )
        .is_ok_and(|r| r.is_satisfied())
    }
}

#[test]
fn recorded_history_uses_original_pair_and_total_dummy_query() {
    for (version, root, route) in [
        (0, 0, 1),
        (1, 81, 1),
        (2, 82, 2),
        (1, 82, 1),
        (3, 83, 2),
        (u64::MAX, 1, 2),
        (0, 81, 1),
        (1, 0, 1),
    ] {
        let c = History::new(version, root, route);
        assert!(c.accepts(), "{version}/{root}");
        let mut wrong = c.clone();
        wrong.valid = !wrong.valid;
        assert!(!wrong.accepts(), "result {version}/{root}");
        wrong = c.clone();
        wrong.selector = 21 - wrong.selector;
        assert!(!wrong.accepts(), "selector {version}/{root}");
    }
    let mut alias = History::new(1, 81, 1);
    // Exactly p is not canonical; decode selects zero, retains false, and
    // authenticates the deterministic version1 dummy query.
    let mut modulus = (-Fp::ONE).to_repr();
    for byte in &mut modulus {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    alias.request[362..394].copy_from_slice(&modulus);
    alias.valid = false;
    assert!(alias.accepts());
    alias.valid = true;
    assert!(!alias.accepts());
}

#[test]
fn every_history_path_word_and_wrong_authenticated_route_reject() {
    let c = History::new(1, 81, 1);
    for i in 0..36 {
        let mut wrong = c.clone();
        wrong.opening[i] += Fp::ONE;
        assert!(!wrong.accepts(), "path cell {i}");
    }
    // This sentinel is authenticated but does not bracket version1.
    for claimed in [false, true] {
        let mut wrong = History::new(1, 81, 0);
        wrong.valid = claimed;
        assert!(!wrong.accepts());
    }
    let mut wrong_root = c.clone();
    wrong_root.root += Fp::ONE;
    assert!(!wrong_root.accepts());
    let known = synthesize(&c, 16, None).unwrap();
    let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    let rows = known
        .tables
        .advice_assigned()
        .iter()
        .map(|lane| lane.iter().rposition(|v| *v).map_or(0, |i| i + 1))
        .collect::<Vec<_>>();
    eprintln!("Receive recorded-history depth32 component lane rows: {rows:?}");
}
