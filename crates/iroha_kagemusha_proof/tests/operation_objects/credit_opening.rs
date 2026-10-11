//! Total credit-status membership binding, including sentinel and alias attacks.

use super::*;
use iroha_kagemusha_proof::{
    operation_relation::objects::credit_opening::CreditOpeningCells,
    tree::{INDEXED_LEAF_DOMAIN, INDEXED_NODE_DOMAIN, path_root},
};

#[derive(Clone)]
struct Opening {
    tape: Vec<u8>,
    expected: [Fp; 3],   // root, credit, Payment
    verdicts: [bool; 2], // body, bound membership
    known: bool,
}
impl Circuit<Fp> for Opening {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        ObjectCircuit::configure(meta)
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(c.glue);
        let mut range = RunningSumChip::new(c.range);
        let mut hash = SpongeChip::new(c.hash);
        let mut bytes = BytesChip::new(c.bytes);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "credit opening",
            |mut region| {
                let tape = self
                    .tape
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
                    &tape,
                    &CreditOpeningCells::primary_segments(),
                    &CreditOpeningCells::secondary_segments(),
                )?;
                let opening = CreditOpeningCells::from_run(
                    &mut glue,
                    &mut range,
                    &mut hash,
                    &mut region,
                    &run,
                )?;
                let expected = glue.witnesses(
                    &mut region,
                    &self
                        .expected
                        .iter()
                        .map(|v| {
                            if self.known {
                                Value::known(*v)
                            } else {
                                Value::unknown()
                            }
                        })
                        .collect::<Vec<_>>(),
                )?;
                let bound = opening.bind(
                    &mut glue,
                    &mut region,
                    &expected[0],
                    &expected[1],
                    &expected[2],
                )?;
                Ok([
                    opening.digest().clone(),
                    opening.root().clone(),
                    opening.valid().word().clone(),
                    bound.word().clone(),
                    opening.credit_id().clone(),
                    opening.payment_digest().clone(),
                    opening.burned().word().clone(),
                ])
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}
impl Opening {
    fn canonical(&self, offset: usize) -> Fp {
        Fp::from_repr(self.tape[offset..offset + 32].try_into().expect("field"))
            .into_option()
            .unwrap_or(Fp::ZERO)
    }
    fn root(&self) -> Fp {
        let credit = self.canonical(0);
        let payment = self.canonical(32);
        let burned = Fp::from(u64::from(self.tape[64] == 1));
        let value = hash_with_domain(u64::from_le_bytes(*b"kgwcdig1"), &[credit, payment, burned]);
        let leaf = hash_with_domain(INDEXED_LEAF_DOMAIN, &[credit, value, self.canonical(65)]);
        let slot = u32::from_le_bytes(self.tape[97..101].try_into().expect("slot"));
        let siblings = (0..32)
            .map(|i| self.canonical(101 + i * 32))
            .collect::<Vec<_>>();
        path_root(INDEXED_NODE_DOMAIN, leaf, u64::from(slot), &siblings)
    }
    fn public(&self) -> Vec<Fp> {
        vec![
            p_bytes_native(u64::from_le_bytes(*b"kgwcopn1"), &self.tape),
            self.root(),
            Fp::from(u64::from(self.verdicts[0])),
            Fp::from(u64::from(self.verdicts[1])),
            self.canonical(0),
            self.canonical(32),
            Fp::from(u64::from(self.tape[64] == 1)),
            Fp::ZERO,
        ]
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 13, &[self.public()], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn rejects(mut self, body_valid: bool, reason: &str) {
        self.verdicts = [body_valid, false];
        assert!(self.accepts(), "total {reason}");
        self.verdicts[1] = true;
        assert!(!self.accepts(), "forged membership {reason}");
        if !body_valid {
            self.verdicts = [true, false];
            assert!(!self.accepts(), "forged body {reason}");
        }
    }
}
fn base() -> Opening {
    let j = fixture();
    let vector = &j["poseidon"]["credit_digest_opening"];
    let tape = decode(vector["credit_opening_hex"].as_str().expect("hex"));
    assert_eq!(tape.len(), CreditOpeningCells::BYTES);
    let mut c = Opening {
        tape,
        expected: [Fp::ZERO; 3],
        verdicts: [true; 2],
        known: true,
    };
    c.expected = [
        field(vector["membership"]["root_hex"].as_str().expect("root")),
        c.canonical(0),
        c.canonical(32),
    ];
    assert_eq!(c.root(), c.expected[0]);
    let digest = j["poseidon"]["large_input_digests"]
        .as_array()
        .expect("digests")
        .iter()
        .find(|v| v["domain"].as_str() == Some("kgwcopn1"))
        .expect("opening");
    assert_eq!(
        c.public()[0],
        field(digest["digest_hex"].as_str().expect("digest"))
    );
    c
}

#[test]
fn credit_status_opening_matches_native_and_cannot_use_absence_or_aliases() {
    let c = base();
    assert!(c.accepts());
    for i in 0..3 {
        let mut wrong = c.clone();
        wrong.expected[i] += Fp::ONE;
        wrong.rejects(true, "foreign authenticated root/credit/Payment");
    }
    for i in 0..32 {
        let mut wrong = c.clone();
        wrong.tape[101 + i * 32] ^= 1;
        wrong.rejects(true, "altered sibling");
    }
    for offset in [0, 32, 65].into_iter().chain((0..32).map(|i| 101 + i * 32)) {
        let mut wrong = c.clone();
        wrong.tape[offset..offset + 32].fill(255);
        wrong.rejects(false, "noncanonical field cannot alias");
    }
    for (offset, count) in [(0, 32), (32, 32), (97, 4)] {
        let mut wrong = c.clone();
        wrong.tape[offset..offset + count].fill(0);
        wrong.rejects(false, "zero identity or sentinel slot");
    }
    for raw in [2, 255] {
        let mut wrong = c.clone();
        wrong.tape[64] = raw;
        wrong.rejects(false, "nonboolean burned flag");
    }
    for next in [Fp::ONE, c.canonical(0)] {
        let mut wrong = c.clone();
        wrong.tape[65..97].copy_from_slice(&next.to_repr());
        wrong.expected[0] = wrong.root();
        wrong.rejects(false, "non-increasing next key even with rebound root");
    }
    for slot in [1, u32::MAX] {
        let mut edge = c.clone();
        edge.tape[97..101].copy_from_slice(&slot.to_le_bytes());
        edge.expected[0] = edge.root();
        assert!(edge.accepts(), "all native nonzero slots");
    }
    let mut burned = c.clone();
    burned.tape[64] = 1;
    burned.expected[0] = burned.root();
    assert!(burned.accepts(), "immutable burned record");
    let known = synthesize(&c, 13, None).expect("known");
    let unknown = synthesize(&c.without_witnesses(), 13, None).expect("unknown");
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
