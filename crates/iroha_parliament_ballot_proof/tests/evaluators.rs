//! The relations under three independent test-local evaluators (plain field
//! values, prover polynomials, verifier keys) on random non-Boolean values: the
//! `X^7` coefficient of every prover polynomial is the plain value, and the
//! polynomial at `Delta` is the verifier's value.
//!
//! The evaluators here are written in this file against the backend's
//! `ConstraintSystem` trait; they are not the backend's own evaluators, which
//! accept witness bits only from outside their crate. On Boolean witnesses the
//! plain values are also compared with the backend's plain evaluator.

mod common;

use common::{fx, pad_of, reg_case, secret, vote_case};
use iroha_parliament_ballot_proof::{
    profile::{Profile, Row},
    registration::{self, RegistrationRelation},
    vote::{self, VoteRelation},
};
use iroha_zkp_vole::{
    field::{BinaryField, Gf256},
    quicksilver::{ConstraintSystem, Relation, violated_constraints},
};
use zeroize::Zeroize;

const DEGREE: usize = 7;

fn element(label: &str) -> Gf256 {
    Gf256::from_bytes(&fx(label, 32)).expect("32 bytes")
}

/// Plain evaluation over the field.
struct PlainSystem {
    values: Vec<Gf256>,
    out: Vec<Gf256>,
}

#[derive(Clone, Copy)]
struct Plain(Gf256);

impl Zeroize for Plain {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ConstraintSystem for PlainSystem {
    type Field = Gf256;
    type Value = Plain;

    fn witness(&self, index: usize) -> Plain {
        Plain(self.values[index])
    }

    fn constant(&self, value: Gf256) -> Plain {
        Plain(value)
    }

    fn add(&self, a: Plain, b: Plain) -> Plain {
        Plain(a.0 + b.0)
    }

    fn mul(&self, a: Plain, b: Plain) -> Plain {
        Plain(a.0 * b.0)
    }

    fn scale(&self, a: Plain, scalar: Gf256) -> Plain {
        Plain(a.0 * scalar)
    }

    fn constrain(&mut self, value: Plain) {
        self.out.push(value.0);
    }
}

/// Prover evaluation: polynomials in `X` on `V_i + w_i X`.
struct ProverSystem {
    values: Vec<Gf256>,
    tags: Vec<Gf256>,
    out: Vec<[Gf256; DEGREE + 1]>,
}

#[derive(Clone, Copy)]
struct Poly {
    coefficients: [Gf256; DEGREE + 1],
    degree: usize,
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.coefficients.zeroize();
        self.degree = 0;
    }
}

/// `value * X^shift`.
fn shifted(value: &Poly, shift: usize) -> [Gf256; DEGREE + 1] {
    let mut out = [Gf256::ZERO; DEGREE + 1];
    for (index, coefficient) in value.coefficients.iter().enumerate() {
        if index + shift <= DEGREE {
            out[index + shift] = *coefficient;
        } else {
            assert_eq!(*coefficient, Gf256::ZERO, "degree overflow");
        }
    }
    out
}

impl ConstraintSystem for ProverSystem {
    type Field = Gf256;
    type Value = Poly;

    fn witness(&self, index: usize) -> Poly {
        let mut coefficients = [Gf256::ZERO; DEGREE + 1];
        coefficients[0] = self.tags[index];
        coefficients[1] = self.values[index];
        Poly {
            coefficients,
            degree: 1,
        }
    }

    fn constant(&self, value: Gf256) -> Poly {
        let mut coefficients = [Gf256::ZERO; DEGREE + 1];
        coefficients[0] = value;
        Poly {
            coefficients,
            degree: 0,
        }
    }

    fn add(&self, a: Poly, b: Poly) -> Poly {
        let degree = a.degree.max(b.degree);
        let left = shifted(&a, degree - a.degree);
        let right = shifted(&b, degree - b.degree);
        Poly {
            coefficients: core::array::from_fn(|i| left[i] + right[i]),
            degree,
        }
    }

    fn mul(&self, a: Poly, b: Poly) -> Poly {
        let degree = a.degree + b.degree;
        assert!(degree <= DEGREE, "degree overflow");
        let mut coefficients = [Gf256::ZERO; DEGREE + 1];
        for i in 0..=a.degree {
            for j in 0..=b.degree {
                coefficients[i + j] += a.coefficients[i] * b.coefficients[j];
            }
        }
        Poly {
            coefficients,
            degree,
        }
    }

    fn scale(&self, a: Poly, scalar: Gf256) -> Poly {
        Poly {
            coefficients: a.coefficients.map(|coefficient| coefficient * scalar),
            degree: a.degree,
        }
    }

    fn constrain(&mut self, value: Poly) {
        self.out.push(shifted(&value, DEGREE - value.degree));
    }
}

/// Verifier evaluation: values at `Delta` from the keys `V_i + w_i Delta`.
struct VerifierSystem {
    keys: Vec<Gf256>,
    powers: [Gf256; DEGREE + 1],
    out: Vec<Gf256>,
}

#[derive(Clone, Copy)]
struct Key {
    value: Gf256,
    degree: usize,
}

impl Zeroize for Key {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.degree = 0;
    }
}

impl ConstraintSystem for VerifierSystem {
    type Field = Gf256;
    type Value = Key;

    fn witness(&self, index: usize) -> Key {
        Key {
            value: self.keys[index],
            degree: 1,
        }
    }

    fn constant(&self, value: Gf256) -> Key {
        Key { value, degree: 0 }
    }

    fn add(&self, a: Key, b: Key) -> Key {
        let degree = a.degree.max(b.degree);
        Key {
            value: a.value * self.powers[degree - a.degree]
                + b.value * self.powers[degree - b.degree],
            degree,
        }
    }

    fn mul(&self, a: Key, b: Key) -> Key {
        Key {
            value: a.value * b.value,
            degree: a.degree + b.degree,
        }
    }

    fn scale(&self, a: Key, scalar: Gf256) -> Key {
        Key {
            value: a.value * scalar,
            degree: a.degree,
        }
    }

    fn constrain(&mut self, value: Key) {
        self.out
            .push(value.value * self.powers[DEGREE - value.degree]);
    }
}

/// Run `relation` on the three evaluators with the field values `values` and
/// check the two identities for every constraint. Returns the plain values.
fn agree<R: Relation<Gf256>>(
    relation: &R,
    public: &R::PublicInput,
    values: Vec<Gf256>,
    label: &str,
) -> Vec<Gf256> {
    let count = values.len();
    assert_eq!(count, relation.witness_bits());
    // Tags from a short seed, expanded by multiplication so that the test does
    // not hash 36,000 times in a debug build.
    let step = element(&format!("{label}/tag-step"));
    let mut tag = element(&format!("{label}/tag"));
    let tags: Vec<Gf256> = (0..count)
        .map(|_| {
            tag = tag * step + Gf256::ONE;
            tag
        })
        .collect();
    let delta = element(&format!("{label}/delta"));
    let mut powers = [Gf256::ONE; DEGREE + 1];
    for index in 1..=DEGREE {
        powers[index] = powers[index - 1] * delta;
    }
    let keys = tags
        .iter()
        .zip(&values)
        .map(|(tag, value)| *tag + *value * delta)
        .collect();

    let mut plain = PlainSystem {
        values: values.clone(),
        out: Vec::new(),
    };
    relation.emit(public, &mut plain);
    let mut prover = ProverSystem {
        values,
        tags,
        out: Vec::new(),
    };
    relation.emit(public, &mut prover);
    let mut verifier = VerifierSystem {
        keys,
        powers,
        out: Vec::new(),
    };
    relation.emit(public, &mut verifier);

    assert_eq!(plain.out.len(), relation.constraints());
    assert_eq!(prover.out.len(), relation.constraints());
    assert_eq!(verifier.out.len(), relation.constraints());
    for (index, polynomial) in prover.out.iter().enumerate() {
        assert_eq!(polynomial[DEGREE], plain.out[index], "constraint {index}");
        let at_delta = polynomial
            .iter()
            .rev()
            .fold(Gf256::ZERO, |acc, coefficient| acc * delta + *coefficient);
        assert_eq!(at_delta, verifier.out[index], "constraint {index}");
    }
    plain.out
}

/// Field values that agree with the bits of `witness` except at every
/// `stride`-th coordinate, which is a random non-Boolean element.
fn mixed_values(witness: &[u8], stride: usize, label: &str) -> Vec<Gf256> {
    let step = element(&format!("{label}/value-step"));
    let mut random = element(&format!("{label}/value"));
    (0..8 * witness.len())
        .map(|i| {
            random = random * step + Gf256::ONE;
            if stride != 0 && i % stride == 0 {
                random
            } else {
                Gf256::from_bit(witness[i / 8] >> (i % 8))
            }
        })
        .collect()
}

/// The indices of the non-zero plain values, as the backend numbers them.
fn nonzero(plain: &[Gf256], witness_bits: usize) -> Vec<usize> {
    plain
        .iter()
        .enumerate()
        .filter(|(_, value)| **value != Gf256::ZERO)
        .map(|(index, _)| witness_bits + index)
        .collect()
}

#[test]
fn the_registration_relation_is_one_polynomial_system_on_all_evaluators() {
    let case = reg_case(Row::Candidate);
    let profile = Profile::new(case.row).expect("tables");
    let instance = case.statement.instance(&profile).expect("valid");
    let witness = registration::witness(
        instance.public(),
        &secret(&case.secret),
        &pad_of(&case.tape),
    )
    .to_vec();
    // Honest bits: every plain value is zero, as the backend's evaluator says.
    let plain = agree(
        &RegistrationRelation,
        instance.public(),
        mixed_values(&witness, 0, "reg/honest"),
        "reg/honest",
    );
    assert!(nonzero(&plain, 35_840).is_empty());
    // Random non-Boolean values everywhere, and in every seventh coordinate.
    let plain = agree(
        &RegistrationRelation,
        instance.public(),
        mixed_values(&witness, 1, "reg/random"),
        "reg/random",
    );
    assert!(nonzero(&plain, 35_840).len() > 36_000);
    agree(
        &RegistrationRelation,
        instance.public(),
        mixed_values(&witness, 7, "reg/mixed"),
        "reg/mixed",
    );
}

#[test]
fn the_vote_relation_is_one_polynomial_system_on_all_evaluators() {
    let case = vote_case(Row::Candidate, 3, 1);
    let profile = Profile::new(case.row).expect("tables");
    let instance = case.statement.instance(&profile).expect("valid");
    let witness = vote::witness(
        instance.public(),
        &secret(&case.secret),
        1,
        &pad_of(&case.tape),
    )
    .to_vec();
    let plain = agree(
        &VoteRelation,
        instance.public(),
        mixed_values(&witness, 0, "vote/honest"),
        "vote/honest",
    );
    assert!(nonzero(&plain, 53_504).is_empty());
    let plain = agree(
        &VoteRelation,
        instance.public(),
        mixed_values(&witness, 1, "vote/random"),
        "vote/random",
    );
    // The two retained prefix constraints at j = 0 are identically zero.
    assert_eq!(plain[0], Gf256::ZERO);
    assert_eq!(plain[33], Gf256::ZERO);
    assert!(nonzero(&plain, 53_504).len() > 36_000);
    // A Boolean but invalid witness: the same constraints fail here and in the
    // backend's plain evaluator.
    let wrong = vote::witness(
        instance.public(),
        &secret(&case.secret),
        2,
        &pad_of(&case.tape),
    )
    .to_vec();
    let plain = agree(
        &VoteRelation,
        instance.public(),
        mixed_values(&wrong, 0, "vote/wrong"),
        "vote/wrong",
    );
    assert_eq!(
        Ok(nonzero(&plain, 53_504)),
        violated_constraints::<Gf256, _>(&VoteRelation, instance.public(), &wrong)
    );
}
