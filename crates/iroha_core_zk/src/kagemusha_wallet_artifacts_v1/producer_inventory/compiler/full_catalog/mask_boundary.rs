//! Exact masked-boundary predicate on the final, strictly imported Omega original.
//!
//! This test-only check substitutes actual fixed evaluations into sparse formal
//! Fq polynomials. It proves identities for every advice/instance assignment,
//! not sampled witnesses. It does not establish recursive security or C12.

use std::collections::BTreeMap;

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Fq};
use iroha_plonk::{
    DescriptorBinding,
    cs::{
        descriptor::{CurveV1, ExprNodeV1, ExprV1, InstanceModeV1, ProofSuffixV1, QueryV1},
        descriptor_v2::{ProtocolDescriptor, TranscriptV2},
    },
    keys::VerifyingKey,
};

use super::{
    DESCRIPTOR_MAX_BYTES_V1, OriginalSourceV1, ProducerInventoryV1, VERIFYING_KEY_MAX_BYTES_V1,
    read,
};

type Check<T> = Result<T, String>;
const MAX_TERMS: usize = 100_000;

// Same variable for repeated/aliased queries into the same physical cell.
// Instance variables stay formal; only advice tail cells are randomized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Variable {
    instance: bool,
    column: u32,
    row: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Polynomial(BTreeMap<Vec<Variable>, Fq>);

impl Polynomial {
    fn constant(value: Fq) -> Self {
        let terms = if value == Fq::ZERO {
            BTreeMap::new()
        } else {
            BTreeMap::from([(Vec::new(), value)])
        };
        Self(terms)
    }

    fn variable(variable: Variable) -> Self {
        Self(BTreeMap::from([(vec![variable], Fq::ONE)]))
    }

    fn add_term(&mut self, term: Vec<Variable>, value: Fq) -> Check<()> {
        let sum = self.0.get(&term).copied().unwrap_or(Fq::ZERO) + value;
        if sum == Fq::ZERO {
            self.0.remove(&term);
        } else {
            self.0.insert(term, sum);
        }
        if self.0.len() > MAX_TERMS {
            return Err("symbolic term cap".into());
        }
        Ok(())
    }

    fn add(mut self, other: Self) -> Check<Self> {
        for (term, value) in other.0 {
            self.add_term(term, value)?;
        }
        Ok(self)
    }

    fn scale(mut self, value: Fq) -> Self {
        if value == Fq::ZERO {
            self.0.clear();
        } else {
            for coefficient in self.0.values_mut() {
                *coefficient *= value;
            }
        }
        self
    }

    fn multiply(self, other: Self) -> Check<Self> {
        if self.0.len().saturating_mul(other.0.len()) > 10 * MAX_TERMS {
            return Err("symbolic product cap".into());
        }
        let mut output = Self::constant(Fq::ZERO);
        for (left, a) in self.0 {
            for (right, b) in &other.0 {
                let mut term = left.clone();
                term.extend_from_slice(right);
                term.sort_unstable();
                output.add_term(term, a * b)?;
            }
        }
        Ok(output)
    }

    fn touches_tail(&self, usable: usize) -> bool {
        self.0
            .keys()
            .flatten()
            .any(|variable| !variable.instance && variable.row >= usable)
    }
}

#[derive(Clone, Debug)]
struct Row {
    fixed: Vec<Fq>,
    sigma: Vec<Fq>,
}

fn canonical(bytes: [u8; 32]) -> Check<Fq> {
    Option::from(Fq::from_repr(bytes)).ok_or_else(|| "noncanonical Fq".into())
}

fn dimensions(descriptor: &ProtocolDescriptor) -> Check<(usize, usize)> {
    let n = 1_usize
        .checked_shl(u32::from(descriptor.k))
        .ok_or("domain size")?;
    let usable = n
        .checked_sub(usize::from(descriptor.blinding_factors) + 1)
        .filter(|usable| *usable > 1)
        .ok_or("usable rows")?;
    if u32::from(descriptor.k) > Fq::S {
        return Err("field domain size".into());
    }
    Ok((n, usable))
}

fn selected_rows(n: usize, usable: usize) -> Vec<usize> {
    [0, usable - 1].into_iter().chain(usable..n).collect()
}

fn omega(k: u8) -> Fq {
    let mut root = Fq::ROOT_OF_UNITY;
    for _ in u32::from(k)..Fq::S {
        root = root.square();
    }
    root
}

fn rotated(row: usize, rotation: i32, n: usize) -> Check<usize> {
    match rotation {
        -1 => Ok(if row == 0 { n - 1 } else { row - 1 }),
        0 => Ok(row),
        1 => Ok(if row + 1 == n { 0 } else { row + 1 }),
        _ => Err("unsupported rotation".into()),
    }
}

fn symbolic(
    descriptor: &ProtocolDescriptor,
    rows: &BTreeMap<usize, Row>,
    row: usize,
    n: usize,
    expression: &ExprV1,
) -> Check<Polynomial> {
    let query = |queries: &[QueryV1], index: u32, instance: bool| -> Check<Polynomial> {
        let query = queries.get(index as usize).ok_or("query index")?;
        Ok(Polynomial::variable(Variable {
            instance,
            column: query.column,
            row: rotated(row, query.rotation, n)?,
        }))
    };
    let mut stack: Vec<Polynomial> = Vec::new();
    for node in expression {
        // Exhaustive typed dispatch: unknown wire tags fail descriptor decode;
        // adding a new node requires an explicit symbolic interpretation here.
        let value = match *node {
            ExprNodeV1::Constant(value) => Polynomial::constant(canonical(value)?),
            ExprNodeV1::Fixed(index) => {
                let query = descriptor
                    .fixed_queries
                    .get(index as usize)
                    .ok_or("fixed query index")?;
                if query.rotation != 0 {
                    return Err("unsupported fixed rotation".into());
                }
                let value = rows
                    .get(&row)
                    .and_then(|values| values.fixed.get(query.column as usize))
                    .ok_or("fixed row/column")?;
                Polynomial::constant(*value)
            }
            ExprNodeV1::Advice(index) => query(&descriptor.advice_queries, index, false)?,
            ExprNodeV1::Instance(index) => query(&descriptor.instance_queries, index, true)?,
            ExprNodeV1::Negated | ExprNodeV1::Scaled(_) => {
                let value = stack.pop().ok_or("unary stack")?;
                value.scale(match *node {
                    ExprNodeV1::Scaled(bytes) => canonical(bytes)?,
                    _ => -Fq::ONE,
                })
            }
            ExprNodeV1::Sum | ExprNodeV1::Product => {
                let right = stack.pop().ok_or("binary stack")?;
                let left = stack.pop().ok_or("binary stack")?;
                if *node == ExprNodeV1::Sum {
                    left.add(right)?
                } else {
                    left.multiply(right)?
                }
            }
        };
        stack.push(value);
        if stack.len() > 1024 {
            return Err("expression stack cap".into());
        }
    }
    if stack.len() != 1 {
        return Err("final expression stack".into());
    }
    stack.pop().ok_or_else(|| "empty expression".into())
}

fn check_boundary(descriptor: &ProtocolDescriptor, rows: &BTreeMap<usize, Row>) -> Check<()> {
    let (n, usable) = dimensions(descriptor)?;
    for query in &descriptor.fixed_queries {
        if query.rotation != 0 || query.column >= descriptor.num_fixed_columns {
            return Err("unsupported fixed query".into());
        }
    }
    for (queries, columns) in [
        (
            &descriptor.advice_queries,
            descriptor.num_advice_columns as usize,
        ),
        (
            &descriptor.instance_queries,
            descriptor.instance_lengths.len(),
        ),
    ] {
        for query in queries {
            rotated(0, query.rotation, n)?;
            if query.column as usize >= columns {
                return Err("query column".into());
            }
        }
    }
    let root = omega(descriptor.k);
    for row in selected_rows(n, usable) {
        let values = rows.get(&row).ok_or("missing boundary row")?;
        if values.fixed.len() != descriptor.num_fixed_columns as usize
            || values.sigma.len() != descriptor.permutation.len()
        {
            return Err("boundary column count".into());
        }
        if row >= usable {
            if values.fixed.iter().any(|value| *value != Fq::ZERO) {
                return Err(format!("nonzero fixed tail row={row}"));
            }
            let mut expected = root.pow_vartime([u64::try_from(row).map_err(|_| "row extent")?]);
            for value in &values.sigma {
                if *value != expected {
                    return Err(format!("tail copy not fixed row={row}"));
                }
                expected *= Fq::DELTA;
            }
        }
        for (gate, expressions) in descriptor.gates.iter().enumerate() {
            for (index, expression) in expressions.iter().enumerate() {
                let polynomial = symbolic(descriptor, rows, row, n, expression)?;
                if polynomial.touches_tail(usable) {
                    return Err(format!(
                        "gate tail dependence row={row} gate={gate} expr={index}"
                    ));
                }
                if row >= usable && !polynomial.0.is_empty() {
                    return Err(format!(
                        "tail gate not zero row={row} gate={gate} expr={index}"
                    ));
                }
            }
        }
        if row < usable {
            for (lookup, pair) in descriptor.lookups.iter().enumerate() {
                for (side, expressions) in [("input", &pair.inputs), ("table", &pair.tables)] {
                    for (index, expression) in expressions.iter().enumerate() {
                        if symbolic(descriptor, rows, row, n, expression)?.touches_tail(usable) {
                            return Err(format!(
                                "lookup tail dependence row={row} lookup={lookup} side={side} expr={index}"
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn artifact_rows(
    original: &[u8],
    descriptor: &ProtocolDescriptor,
    descriptor_digest: &[u8; 32],
    verifying_key: &[u8],
) -> Check<BTreeMap<usize, Row>> {
    let (n, usable) = dimensions(descriptor)?;
    let columns = descriptor.num_fixed_columns as usize + descriptor.permutation.len();
    let offset = 76_usize
        .checked_add(verifying_key.len())
        .ok_or("PK offset")?;
    let expected = columns
        .checked_mul(n)
        .and_then(|size| size.checked_mul(32))
        .and_then(|size| size.checked_add(offset))
        .ok_or("PK extent")?;
    if original.len() != expected
        || original.get(..8) != Some(b"PIPAPK01".as_slice())
        || original.get(8..40) != Some(descriptor_digest.as_slice())
    {
        return Err("PK framing/binding/extent".into());
    }
    let key_len = u32::from_le_bytes(original[40..44].try_into().map_err(|_| "PK key length")?);
    if key_len as usize != verifying_key.len()
        || original.get(44..offset - 32) != Some(verifying_key)
    {
        return Err("PK exact VK".into());
    }
    let mut rows = BTreeMap::new();
    for row in selected_rows(n, usable) {
        let mut values = Vec::with_capacity(columns);
        for column in 0..columns {
            let start = offset + (column * n + row) * 32;
            values.push(canonical(
                original[start..start + 32]
                    .try_into()
                    .map_err(|_| "PK scalar")?,
            )?);
        }
        let sigma = values.split_off(descriptor.num_fixed_columns as usize);
        rows.insert(
            row,
            Row {
                fixed: values,
                sigma,
            },
        );
    }
    Ok(rows)
}

/// Check the exact final role after the compiler's mandatory source import.
pub(super) fn assert_final_omega(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
) {
    let original = inventory.member(inventory.omega).expect("final Omega role");
    let descriptor = read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
    // Explicit V2 decoding validates all expression tags and canonical framing.
    let binding = DescriptorBinding::decode_v2(&descriptor).unwrap();
    let d = binding.descriptor();
    assert_eq!(d.curve, CurveV1::Pallas);
    assert_eq!(d.transcript, TranscriptV2::KagemushaPoseidonRp57Base);
    assert_eq!(d.instance_mode, InstanceModeV1::Direct);
    assert_eq!(d.proof_suffix, ProofSuffixV1::FoldedGenerator);
    assert_eq!((d.k, d.blinding_factors, d.degree), (16, 5, 9));
    assert_eq!((d.num_fixed_columns, d.num_advice_columns), (12, 11));
    assert_eq!((d.permutation.len(), d.lookups.len()), (6, 1));
    assert_eq!((d.permutation_chunk_len, d.quotient_pieces), (7, 8));
    let key = read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1).unwrap();
    VerifyingKey::<Ep>::read(&key, &binding).unwrap();
    let expected_bytes =
        76 + key.len() + (d.num_fixed_columns as usize + d.permutation.len()) * binding.n() * 32;
    let proving_key = read(source, original.proving_key, expected_bytes).unwrap();
    let rows = artifact_rows(&proving_key, d, binding.digest(), &key).unwrap();
    check_boundary(d, &rows).unwrap();
    eprintln!(
        "OMEGA_MASK_BOUNDARY final_role={} descriptor_sha256={} vk_sha256={} pk_sha256={} rows={} exact_fq=true passed=true C12_closed=false",
        inventory.omega,
        hex::encode(original.descriptor.sha256),
        hex::encode(original.verifying_key.sha256),
        hex::encode(original.proving_key.sha256),
        rows.len(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_plonk::cs::descriptor::{
        ColumnKindV1, LookupKindV1, LookupV1, PermutationColumnV1, SelectorsV1,
    };

    // Small DATA for the same exact predicate; no witness or key generation.
    fn fixture() -> (ProtocolDescriptor, BTreeMap<usize, Row>) {
        let descriptor = ProtocolDescriptor {
            protocol_version: 1,
            curve: CurveV1::Pallas,
            base_modulus: CurveV1::Pallas.base_modulus(),
            scalar_modulus: CurveV1::Pallas.scalar_modulus(),
            params_digest: [1; 32],
            k: 3,
            transcript: TranscriptV2::KagemushaPoseidonRp57Base,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
            degree: 3,
            blinding_factors: 1,
            permutation_chunk_len: 1,
            quotient_pieces: 2,
            lookup_kind: LookupKindV1::Halo2Permuted,
            num_fixed_columns: 1,
            num_advice_columns: 1,
            instance_lengths: vec![1],
            fixed_queries: vec![QueryV1 {
                column: 0,
                rotation: 0,
            }],
            advice_queries: vec![QueryV1 {
                column: 0,
                rotation: 0,
            }],
            instance_queries: vec![QueryV1 {
                column: 0,
                rotation: 0,
            }],
            selectors: SelectorsV1 {
                compress: true,
                first_column: 0,
                entries: vec![],
            },
            gates: vec![vec![vec![
                ExprNodeV1::Fixed(0),
                ExprNodeV1::Advice(0),
                ExprNodeV1::Product,
            ]]],
            permutation: vec![
                PermutationColumnV1 {
                    kind: ColumnKindV1::Advice,
                    index: 0,
                },
                PermutationColumnV1 {
                    kind: ColumnKindV1::Fixed,
                    index: 0,
                },
            ],
            lookups: vec![LookupV1 {
                inputs: vec![vec![ExprNodeV1::Advice(0)]],
                tables: vec![vec![ExprNodeV1::Fixed(0)]],
            }],
            instance_types: None,
        };
        let rows = selected_rows(8, 6)
            .into_iter()
            .map(|row| {
                (
                    row,
                    Row {
                        fixed: vec![if row < 6 { Fq::ONE } else { Fq::ZERO }],
                        sigma: vec![
                            omega(3).pow_vartime([u64::try_from(row).unwrap()]),
                            Fq::DELTA * omega(3).pow_vartime([u64::try_from(row).unwrap()]),
                        ],
                    },
                )
            })
            .collect();
        (descriptor, rows)
    }

    #[test]
    fn exact_cancellation_and_physical_query_aliases_pass() {
        let (mut d, rows) = fixture();
        check_boundary(&d, &rows).unwrap();
        d.advice_queries.push(d.advice_queries[0]);
        d.gates.push(vec![vec![
            ExprNodeV1::Advice(0),
            ExprNodeV1::Advice(1),
            ExprNodeV1::Negated,
            ExprNodeV1::Sum,
            ExprNodeV1::Instance(0),
            ExprNodeV1::Product,
            ExprNodeV1::Scaled(Fq::from(7).to_repr()),
        ]]);
        check_boundary(&d, &rows).unwrap();
        d.advice_queries.push(QueryV1 {
            column: 0,
            rotation: 1,
        });
        // Expand both products before cancellation, even where a_next is a pad.
        d.gates.push(vec![vec![
            ExprNodeV1::Advice(0),
            ExprNodeV1::Advice(2),
            ExprNodeV1::Product,
            ExprNodeV1::Advice(2),
            ExprNodeV1::Advice(0),
            ExprNodeV1::Product,
            ExprNodeV1::Negated,
            ExprNodeV1::Sum,
        ]]);
        check_boundary(&d, &rows).unwrap();
    }

    #[test]
    fn next_and_previous_usable_gates_cannot_touch_randomized_tail() {
        for (rotation, row) in [(1, 5), (-1, 0)] {
            let (mut d, rows) = fixture();
            d.advice_queries.push(QueryV1 {
                column: 0,
                rotation,
            });
            // q * (a_rot - a_cur): all tail fixed/copy checks still pass.
            d.gates[0][0] = vec![
                ExprNodeV1::Fixed(0),
                ExprNodeV1::Advice(1),
                ExprNodeV1::Advice(0),
                ExprNodeV1::Negated,
                ExprNodeV1::Sum,
                ExprNodeV1::Product,
            ];
            assert!(
                check_boundary(&d, &rows)
                    .unwrap_err()
                    .contains(&format!("gate tail dependence row={row}"))
            );
        }
    }

    #[test]
    fn tail_fixed_copy_and_nonzero_gate_mutations_refuse() {
        let (d, rows) = fixture();
        let mut changed = rows.clone();
        changed.get_mut(&6).unwrap().fixed[0] = Fq::ONE;
        assert!(
            check_boundary(&d, &changed)
                .unwrap_err()
                .contains("nonzero fixed tail")
        );
        let mut changed = rows.clone();
        changed.get_mut(&7).unwrap().sigma[1] += Fq::ONE;
        assert!(
            check_boundary(&d, &changed)
                .unwrap_err()
                .contains("tail copy not fixed")
        );
        let mut d = d;
        d.gates
            .push(vec![vec![ExprNodeV1::Constant(Fq::ONE.to_repr())]]);
        assert!(
            check_boundary(&d, &rows)
                .unwrap_err()
                .contains("tail gate not zero")
        );
    }

    #[test]
    fn either_lookup_side_refuses_next_and_previous_tail_dependence() {
        for rotation in [-1, 1] {
            for input in [false, true] {
                let (mut d, rows) = fixture();
                d.advice_queries.push(QueryV1 {
                    column: 0,
                    rotation,
                });
                let expressions = if input {
                    &mut d.lookups[0].inputs
                } else {
                    &mut d.lookups[0].tables
                };
                expressions[0] = vec![ExprNodeV1::Advice(1)];
                assert!(
                    check_boundary(&d, &rows)
                        .unwrap_err()
                        .contains("lookup tail dependence")
                );
            }
        }
    }

    #[test]
    fn unsupported_queries_and_malformed_expressions_refuse() {
        let (d, rows) = fixture();
        for rotation in [-2, 2] {
            let mut changed = d.clone();
            changed.advice_queries[0].rotation = rotation;
            assert!(
                check_boundary(&changed, &rows)
                    .unwrap_err()
                    .contains("unsupported rotation")
            );
        }
        let mut changed = d.clone();
        changed.fixed_queries[0].rotation = 1;
        assert!(
            check_boundary(&changed, &rows)
                .unwrap_err()
                .contains("unsupported fixed query")
        );
        for expression in [
            vec![],
            vec![ExprNodeV1::Product],
            vec![ExprNodeV1::Advice(99)],
            vec![ExprNodeV1::Constant([255; 32])],
            vec![ExprNodeV1::Advice(0), ExprNodeV1::Advice(0)],
        ] {
            let mut changed = d.clone();
            changed.gates[0][0] = expression;
            assert!(check_boundary(&changed, &rows).is_err());
        }
    }

    #[test]
    fn exact_original_table_reader_refuses_binding_framing_and_scalar_mutations() {
        let (d, expected_rows) = fixture();
        let digest = [7; 32];
        let key = [9, 10];
        // Synthetic PK framing only; not a VK, strict source import or key proof.
        let mut original = b"PIPAPK01".to_vec();
        original.extend_from_slice(&digest);
        original.extend_from_slice(&u32::try_from(key.len()).unwrap().to_le_bytes());
        original.extend_from_slice(&key);
        original.extend_from_slice(&[3; 32]); // Opaque copy digest, covered by the full original hash.
        for column in 0..3 {
            for row in 0..8 {
                let value = expected_rows.get(&row).map_or(Fq::ZERO, |values| {
                    if column == 0 {
                        values.fixed[0]
                    } else {
                        values.sigma[column - 1]
                    }
                });
                original.extend_from_slice(&value.to_repr());
            }
        }
        let rows = artifact_rows(&original, &d, &digest, &key).unwrap();
        check_boundary(&d, &rows).unwrap();
        for row in selected_rows(8, 6) {
            assert_eq!(rows[&row].fixed, expected_rows[&row].fixed);
            assert_eq!(rows[&row].sigma, expected_rows[&row].sigma);
        }
        for index in [0, 8, 40, 44] {
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(artifact_rows(&changed, &d, &digest, &key).is_err());
        }
        let mut changed = original.clone();
        changed.push(0);
        assert!(artifact_rows(&changed, &d, &digest, &key).is_err());
        assert!(artifact_rows(&original[..original.len() - 1], &d, &digest, &key).is_err());
        let offset = 76 + key.len() + 6 * 32;
        original[offset..offset + 32].fill(255);
        assert!(
            artifact_rows(&original, &d, &digest, &key)
                .unwrap_err()
                .contains("noncanonical Fq")
        );
    }
}
