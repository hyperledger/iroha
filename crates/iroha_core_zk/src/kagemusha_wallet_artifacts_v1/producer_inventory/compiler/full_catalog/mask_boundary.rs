//! Exact mask predicates on strictly imported Omega/sigma and private Q/A/W originals.
//!
//! This test-only check substitutes actual fixed evaluations into sparse formal
//! field polynomials. It proves identities for every advice/instance assignment,
//! not sampled witnesses. It does not establish recursive security or C12.

use std::collections::{BTreeMap, BTreeSet};

use ff::{Field, PrimeField};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaCurve};
use iroha_plonk::{
    DescriptorBinding, Protocol,
    cs::{
        descriptor::{CurveV1, ExprNodeV1, ExprV1, InstanceModeV1, ProofSuffixV1, QueryV1},
        descriptor_v2::{ProtocolDescriptor, TranscriptV2},
    },
    frontend::Circuit,
    keys::{ProvingKey, SourceBoundVerifyingKeyV2, VerifyingKey, pk::artifact::ReadConfig},
    pcs::ipa::PinnedParams,
    pcs::multiopen::{OpeningPlan, Slot, SlotKind},
    protocol::check_zero_knowledge_budget,
};

use super::{
    ARTIFACT_MAX_COUNT_V1, BlobV1, DESCRIPTOR_MAX_BYTES_V1, OriginalSourceV1, OriginalV1,
    ProducerInventoryV1, VERIFYING_KEY_MAX_BYTES_V1, read,
};

type Check<T> = Result<T, String>;
const MAX_TERMS: usize = 100_000;

trait MaskField: PrimeField<Repr = [u8; 32]> {
    const NAME: &'static str;
    const CURVE: CurveV1;
}
impl MaskField for Fp {
    const NAME: &'static str = "Fp";
    const CURVE: CurveV1 = CurveV1::Vesta;
}
impl MaskField for Fq {
    const NAME: &'static str = "Fq";
    const CURVE: CurveV1 = CurveV1::Pallas;
}

// Same variable for repeated/aliased queries into the same physical cell.
// Instance variables stay formal; only advice tail cells are randomized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Variable {
    instance: bool,
    column: u32,
    row: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Polynomial<F: MaskField = Fq>(BTreeMap<Vec<Variable>, F>);

impl<F: MaskField> Polynomial<F> {
    fn constant(value: F) -> Self {
        let terms = if value == F::ZERO {
            BTreeMap::new()
        } else {
            BTreeMap::from([(Vec::new(), value)])
        };
        Self(terms)
    }

    fn variable(variable: Variable) -> Self {
        Self(BTreeMap::from([(vec![variable], F::ONE)]))
    }

    fn add_term(&mut self, term: Vec<Variable>, value: F) -> Check<()> {
        let sum = self.0.get(&term).copied().unwrap_or(F::ZERO) + value;
        if sum == F::ZERO {
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

    fn scale(mut self, value: F) -> Self {
        if value == F::ZERO {
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
        let mut output = Self::constant(F::ZERO);
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
struct Row<F: MaskField = Fq> {
    fixed: Vec<F>,
    sigma: Vec<F>,
}

fn canonical<F: MaskField>(bytes: [u8; 32]) -> Check<F> {
    Option::from(F::from_repr(bytes)).ok_or_else(|| format!("noncanonical {}", F::NAME))
}

fn dimensions<F: MaskField>(descriptor: &ProtocolDescriptor) -> Check<(usize, usize)> {
    if descriptor.curve != F::CURVE {
        return Err("mask scalar field differs from descriptor".into());
    }
    let n = 1_usize
        .checked_shl(u32::from(descriptor.k))
        .ok_or("domain size")?;
    let usable = n
        .checked_sub(usize::from(descriptor.blinding_factors) + 1)
        .filter(|usable| *usable > 1)
        .ok_or("usable rows")?;
    if u32::from(descriptor.k) > F::S {
        return Err("field domain size".into());
    }
    Ok((n, usable))
}

// Every gate/lookup row that can read randomized advice, plus every tail
// row. Outside this closure no advice variable can be a randomized tail cell.
// Retain the former end rows as redundant checks for the public-role profiles.
fn boundary_rows(
    descriptor: &ProtocolDescriptor,
    n: usize,
    usable: usize,
) -> Check<BTreeSet<usize>> {
    let mut rows: BTreeSet<_> = [0, usable - 1].into_iter().chain(usable..n).collect();
    for query in &descriptor.advice_queries {
        for tail in usable..n {
            rows.insert(shifted(tail, -i64::from(query.rotation), n)?);
        }
    }
    Ok(rows)
}

// Fixed columns are public constants. Read their actual rotated cells, even
// when those cells are outside the mask-dependent evaluation-row closure.
fn public_table_rows(
    descriptor: &ProtocolDescriptor,
    n: usize,
    usable: usize,
) -> Check<BTreeSet<usize>> {
    let evaluation = boundary_rows(descriptor, n, usable)?;
    let mut rows = evaluation.clone();
    for row in evaluation {
        for query in &descriptor.fixed_queries {
            rows.insert(rotated(row, query.rotation, n)?);
        }
    }
    Ok(rows)
}

fn omega<F: MaskField>(k: u8) -> F {
    let mut root = F::ROOT_OF_UNITY;
    for _ in u32::from(k)..F::S {
        root = root.square();
    }
    root
}

fn shifted(row: usize, rotation: i64, n: usize) -> Check<usize> {
    let n = i64::try_from(n).map_err(|_| "domain extent")?;
    if n <= 1 {
        return Err("domain extent".into());
    }
    let row = i64::try_from(row).map_err(|_| "row extent")?;
    if !(0..n).contains(&row) {
        return Err("row extent".into());
    }
    let sum = row.checked_add(rotation).ok_or("rotation extent")?;
    usize::try_from(sum.rem_euclid(n)).map_err(|_| "rotated row extent".into())
}

fn rotated(row: usize, rotation: i32, n: usize) -> Check<usize> {
    shifted(row, i64::from(rotation), n)
}

fn symbolic<F: MaskField>(
    descriptor: &ProtocolDescriptor,
    rows: &BTreeMap<usize, Row<F>>,
    row: usize,
    n: usize,
    expression: &ExprV1,
) -> Check<Polynomial<F>> {
    let query = |queries: &[QueryV1], index: u32, instance: bool| -> Check<Polynomial<F>> {
        let query = queries.get(index as usize).ok_or("query index")?;
        Ok(Polynomial::variable(Variable {
            instance,
            column: query.column,
            row: rotated(row, query.rotation, n)?,
        }))
    };
    let mut stack: Vec<Polynomial<F>> = Vec::new();
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
                let fixed_row = rotated(row, query.rotation, n)?;
                let value = rows
                    .get(&fixed_row)
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
                    _ => -F::ONE,
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

fn check_boundary<F: MaskField>(
    descriptor: &ProtocolDescriptor,
    rows: &BTreeMap<usize, Row<F>>,
) -> Check<()> {
    let (n, usable) = dimensions::<F>(descriptor)?;
    for query in &descriptor.fixed_queries {
        rotated(0, query.rotation, n)?;
        if query.column >= descriptor.num_fixed_columns {
            return Err("fixed query column".into());
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
    let root = omega::<F>(descriptor.k);
    for row in boundary_rows(descriptor, n, usable)? {
        let values = rows.get(&row).ok_or("missing boundary row")?;
        if values.fixed.len() != descriptor.num_fixed_columns as usize
            || values.sigma.len() != descriptor.permutation.len()
        {
            return Err("boundary column count".into());
        }
        if row >= usable {
            if values.fixed.iter().any(|value| *value != F::ZERO) {
                return Err(format!("nonzero fixed tail row={row}"));
            }
            let mut expected = root.pow_vartime([u64::try_from(row).map_err(|_| "row extent")?]);
            for value in &values.sigma {
                if *value != expected {
                    return Err(format!("tail copy not fixed row={row}"));
                }
                expected *= F::DELTA;
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

// The collector is reachable only in cfg(test) compiler builds and is explicitly
// enabled by the complete-catalogue test. It holds at most 64 MiB of scalar cells
// and at most 262,144 rows, with the inventory's original count cap. These are
// retained-cell/count limits, not total process RSS. No proving key is retained.
const MAX_CAPTURE_BYTES: usize = 64 << 20;
const MAX_CAPTURE_ROWS: usize = 1 << 18;

#[derive(Debug)]
struct EncodedRow {
    fixed: Vec<[u8; 32]>,
    sigma: Vec<[u8; 32]>,
}

struct CapturedOriginal {
    identity: OriginalV1,
    rows: BTreeMap<usize, EncodedRow>,
}

#[derive(Default)]
pub(in super::super) struct ImportedRows {
    originals: BTreeMap<[u8; 32], CapturedOriginal>,
    bytes: usize,
    rows: usize,
}

impl ImportedRows {
    pub(in super::super) fn contains(&self, original: OriginalV1) -> bool {
        self.originals
            .get(&original.proving_key.sha256)
            .is_some_and(|captured| captured.identity == original)
    }

    pub(in super::super) fn import<C: PastaCurve, S: Circuit<C::ScalarExt>>(
        &mut self,
        original: OriginalV1,
        bytes: &[u8],
        binding: &DescriptorBinding,
        params: &PinnedParams<C>,
        circuit: &S,
        config: ReadConfig,
    ) -> Check<SourceBoundVerifyingKeyV2<C>> {
        if original.descriptor != BlobV1::of(binding.encoded())
            || original.proving_key != BlobV1::of(bytes)
            || self.originals.contains_key(&original.proving_key.sha256)
            || self.originals.len() >= ARTIFACT_MAX_COUNT_V1
            || bytes.len() > config.maximum_bytes
            || binding.n() > config.maximum_rows
        {
            return Err("compact source capture identity/count".into());
        }
        let d = binding.descriptor();
        let n = binding.n();
        let usable = n
            .checked_sub(usize::from(d.blinding_factors) + 1)
            .filter(|usable| *usable > 1)
            .ok_or("capture usable rows")?;
        let selected = public_table_rows(d, n, usable)?;
        let total_rows = self
            .rows
            .checked_add(selected.len())
            .filter(|count| *count <= MAX_CAPTURE_ROWS)
            .ok_or("capture row budget")?;
        let columns = (d.num_fixed_columns as usize)
            .checked_add(d.permutation.len())
            .ok_or("capture columns")?;
        let size = selected
            .len()
            .checked_mul(columns)
            .and_then(|cells| cells.checked_mul(32))
            .ok_or("capture extent")?;
        let total = self
            .bytes
            .checked_add(size)
            .filter(|v| *v <= MAX_CAPTURE_BYTES)
            .ok_or("capture byte budget")?;
        // This is the ordinary strict source and commitment importer. It is the
        // only authority for reconstructed evaluations; compact bytes contain no
        // tables. Metadata is derived from this same admitted key, avoiding a
        // second commitment import. The owned PK retires at this call's end.
        let key = ProvingKey::from_artifact_v2(bytes, binding, params, circuit, config)
            .map_err(|error| error.to_string())?;
        if original.verifying_key != BlobV1::of(&key.vk().to_bytes()) {
            return Err("compact source capture exact VK".into());
        }
        let rows = selected
            .into_iter()
            .map(|row| {
                (
                    row,
                    EncodedRow {
                        fixed: key
                            .fixed_values()
                            .iter()
                            .map(|column| column[row].to_repr())
                            .collect(),
                        sigma: key
                            .permutation_values()
                            .iter()
                            .map(|column| column[row].to_repr())
                            .collect(),
                    },
                )
            })
            .collect();
        let admitted = SourceBoundVerifyingKeyV2::from_proving_key(&key, None)
            .map_err(|error| error.to_string())?;
        self.originals.insert(
            original.proving_key.sha256,
            CapturedOriginal {
                identity: original,
                rows,
            },
        );
        self.bytes = total;
        self.rows = total_rows;
        Ok(admitted)
    }

    pub(super) fn require_inventory(&self, inventory: &ProducerInventoryV1) -> Check<()> {
        if inventory
            .originals
            .iter()
            .any(|original| !self.contains(*original))
        {
            return Err("missing exact inventory source rows".into());
        }
        Ok(())
    }

    fn artifact_rows<F: MaskField>(
        &self,
        original: &[u8],
        binding: &DescriptorBinding,
        verifying_key: &[u8],
    ) -> Check<BTreeMap<usize, Row<F>>> {
        let descriptor = binding.descriptor();
        let (n, usable) = dimensions::<F>(descriptor)?;
        let identity = OriginalV1 {
            descriptor: BlobV1::of(binding.encoded()),
            verifying_key: BlobV1::of(verifying_key),
            proving_key: BlobV1::of(original),
        };
        let captured = self
            .originals
            .get(&identity.proving_key.sha256)
            .filter(|captured| captured.identity == identity)
            .ok_or("missing exact compact source capture")?;
        let expected = public_table_rows(descriptor, n, usable)?;
        if captured.rows.keys().copied().collect::<BTreeSet<_>>() != expected {
            return Err("missing or substituted public closure rows".into());
        }
        captured
            .rows
            .iter()
            .map(|(&row, values)| {
                if values.fixed.len() != descriptor.num_fixed_columns as usize
                    || values.sigma.len() != descriptor.permutation.len()
                {
                    return Err("captured row column extent".into());
                }
                Ok((
                    row,
                    Row {
                        fixed: values
                            .fixed
                            .iter()
                            .copied()
                            .map(canonical)
                            .collect::<Check<_>>()?,
                        sigma: values
                            .sigma
                            .iter()
                            .copied()
                            .map(canonical)
                            .collect::<Check<_>>()?,
                    },
                ))
            })
            .collect()
    }
}

// Counts independent *domain rows*, not commitment blinds. Blinds are an
// additional independent scalar per commitment and do not replace row rank.
fn fresh_rows(kind: SlotKind, n: usize, b: usize) -> Option<usize> {
    match kind {
        SlotKind::Advice | SlotKind::LookupPermutedInput | SlotKind::LookupPermutedTable => {
            Some(b + 1)
        }
        SlotKind::PermutationProduct | SlotKind::LookupProduct => Some(b),
        SlotKind::Random => Some(n),
        SlotKind::Instance | SlotKind::Fixed | SlotKind::PermutationSigma | SlotKind::Vanishing => {
            None
        }
    }
}

fn opening_report(plan: &OpeningPlan, n: usize, b: usize) -> Check<Vec<String>> {
    let slots = plan.slots();
    let h = Slot::new(SlotKind::Vanishing, 0);
    let r = Slot::new(SlotKind::Random, 0);
    if slots.last().map(|s| s.slot) != Some(r)
        || slots
            .iter()
            .filter(|s| s.slot.kind == SlotKind::Random)
            .count()
            != 1
        || slots
            .iter()
            .filter(|s| s.slot.kind == SlotKind::Vanishing)
            .count()
            != 1
    {
        return Err("h/R uniqueness or R not last".into());
    }
    let h_slot = slots.iter().find(|s| s.slot == h).ok_or("missing h")?;
    let r_slot = slots.last().ok_or("missing R")?;
    if h_slot.set != r_slot.set
        || h_slot.points.len() != 1
        || plan.rotations().get(h_slot.points[0]) != Some(&0)
        || h_slot.points != r_slot.points
    {
        return Err("h/R must share exactly rotation zero".into());
    }
    let n_i64 = i64::try_from(n).map_err(|_| "domain extent")?;
    if n_i64 <= 1 || b >= n || b < 2 {
        return Err("mask dimensions".into());
    }
    let mut reduced = std::collections::BTreeSet::new();
    for rotation in plan.rotations() {
        if !reduced.insert(i64::from(*rotation).rem_euclid(n_i64)) {
            return Err("rotation alias modulo n".into());
        }
    }
    let mut output = Vec::new();
    for slot in slots {
        let rotations: Vec<_> = slot.points.iter().map(|i| plan.rotations()[*i]).collect();
        if slot.slot.kind == SlotKind::Instance {
            return Err("mask predicate requires Direct instances".into());
        }
        if let Some(fresh) = fresh_rows(slot.slot.kind, n, b) {
            let revealed = slot
                .points
                .len()
                .checked_add(1)
                .ok_or("evaluation extent")?;
            let residual = fresh
                .checked_sub(revealed)
                .filter(|v| *v > 0)
                .ok_or("no residual mask rank")?;
            if slot.slot.kind != SlotKind::Random && revealed > b - 1 {
                return Err("S7 opening budget".into());
            }
            output.push(format!("slot={:?}:{} set={} rotations={rotations:?} fresh_rows={fresh} rank_with_x3={revealed} residual={residual}", slot.slot.kind,slot.slot.index,slot.set));
        } else {
            output.push(format!(
                "slot={:?}:{} set={} rotations={rotations:?} fresh_rows=0",
                slot.slot.kind, slot.slot.index, slot.set
            ));
        }
    }
    for (set, points) in plan.sets().iter().enumerate() {
        let members: Vec<_> = slots.iter().filter(|s| s.set == set).collect();
        if members.is_empty() {
            return Err("empty opening group".into());
        }
        let branch = if set == h_slot.set {
            // The production Horner fold walks *forward* slot order. Thus the
            // globally last R is last in this group and has coefficient ONE.
            if members.last().map(|s| s.slot) != Some(r) {
                return Err("R coefficient not one".into());
            }
            "quotient_R_coefficient_one"
        } else if members
            .iter()
            .any(|s| fresh_rows(s.slot.kind, n, b).is_some())
        {
            "residual_witness_pad_requires_nonzero_x1"
        } else if members
            .iter()
            .all(|s| matches!(s.slot.kind, SlotKind::Fixed | SlotKind::PermutationSigma))
        {
            // These evaluations are deterministic public preprocessing. They
            // MUST NOT be sampled uniformly by the outer proof simulator.
            "exact_public_preprocessing"
        } else {
            return Err("uncovered opening group".into());
        };
        let rotations: Vec<_> = points.iter().map(|i| plan.rotations()[*i]).collect();
        output.push(format!("set={set} rotations={rotations:?} branch={branch}"));
    }
    Ok(output)
}

fn assert_opening_mask(binding: &DescriptorBinding, role: &str) {
    let protocol = Protocol::new(binding.descriptor()).expect("actual protocol");
    check_zero_knowledge_budget(&protocol).expect("actual S7 plan");
    let shape = protocol.shape();
    let rows = opening_report(protocol.plan(), shape.n, shape.blinding_factors)
        .expect("opening mask predicate");
    for row in rows {
        eprintln!("PUBLIC_MASK_PLAN role={role} {row}");
    }
    let fresh_scalar_draw_cap = 2 * shape.n
        + shape.num_advice * (shape.blinding_factors + 2)
        + 2 * shape.lookups * (shape.blinding_factors + 2)
        + (shape.permutation_sets + shape.lookups) * (shape.blinding_factors + 1)
        + shape.quotient_pieces
        + 2 * shape.k as usize
        + 3;
    let fresh_blinded_points = shape.num_advice
        + 3 * shape.lookups
        + shape.permutation_sets
        + shape.quotient_pieces
        + 2 * shape.k as usize
        + 3;
    eprintln!(
        "PUBLIC_MASK_SHAPE role={role} n={} b={} degree={} proof_bytes={} groups={} fresh_scalar_draw_cap={fresh_scalar_draw_cap} fresh_blinded_points={fresh_blinded_points} conditional_on_nondegenerate_challenges=true C12_closed=false",
        shape.n,
        shape.blinding_factors,
        shape.degree,
        protocol.proof_length(),
        protocol.plan().sets().len()
    );
}

/// Check every public sigma selector after the same mandatory strict import.
/// This consumes public PK tables only and gives no source-admission shortcut.
pub(super) fn assert_public_sigmas(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
    captured: &ImportedRows,
) {
    for (selector, index) in inventory.sigma.iter().copied().enumerate() {
        let original = inventory.member(index).expect("public sigma role");
        let bytes = read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
        let binding = DescriptorBinding::decode_v2(&bytes).unwrap();
        let d = binding.descriptor();
        assert_eq!(d.curve, CurveV1::Vesta);
        assert_eq!(d.transcript, TranscriptV2::KagemushaPoseidonRp57Base);
        assert_eq!(d.instance_mode, InstanceModeV1::Direct);
        assert_eq!(d.proof_suffix, ProofSuffixV1::FoldedGenerator);
        assert_eq!(d.instance_lengths, [1]);
        assert_eq!((d.blinding_factors, d.degree), (5, 6));
        let expected_k = if matches!(selector, 4 | 5 | 8 | 9) {
            14
        } else {
            12
        };
        assert_eq!(d.k, expected_k);
        let key = read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1).unwrap();
        VerifyingKey::<Eq>::read(&key, &binding).unwrap();
        let expected_bytes = key
            .len()
            .checked_add(108)
            .expect("compact public PK extent");
        let proving_key = read(source, original.proving_key, expected_bytes).unwrap();
        let rows = captured
            .artifact_rows::<Fp>(&proving_key, &binding, &key)
            .unwrap();
        check_boundary(d, &rows).unwrap();
        assert_opening_mask(&binding, &format!("sigma.{selector}"));
        eprintln!(
            "SIGMA_MASK_BOUNDARY selector={selector} role={index} descriptor_sha256={} vk_sha256={} pk_sha256={} rows={} exact_fp=true passed=true C12_closed=false",
            hex::encode(original.descriptor.sha256),
            hex::encode(original.verifying_key.sha256),
            hex::encode(original.proving_key.sha256),
            rows.len()
        );
        // All owned bytes retire here before the next role is read.
    }
}

/// Check the exact final role after the compiler's mandatory source import.
pub(super) fn assert_final_omega(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
    captured: &ImportedRows,
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
    let expected_bytes = key.len().checked_add(108).expect("compact Omega PK extent");
    let proving_key = read(source, original.proving_key, expected_bytes).unwrap();
    let rows = captured
        .artifact_rows::<Fq>(&proving_key, &binding, &key)
        .unwrap();
    check_boundary(d, &rows).unwrap();
    assert_opening_mask(&binding, "Omega");
    eprintln!(
        "OMEGA_MASK_BOUNDARY final_role={} descriptor_sha256={} vk_sha256={} pk_sha256={} rows={} exact_fq=true passed=true C12_closed=false",
        inventory.omega,
        hex::encode(original.descriptor.sha256),
        hex::encode(original.verifying_key.sha256),
        hex::encode(original.proving_key.sha256),
        rows.len(),
    );
}

/// Check every distinct private Q/A/W original after mandatory strict import.
/// Deduplication is by original index, never just the descriptor: equal circuit
/// shape does not establish equality of the public preprocessing tables.
pub(super) fn assert_private_roles(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
    captured: &ImportedRows,
) {
    let mut members = BTreeMap::new();
    for operation in &inventory.operations {
        for (role, indices, curve) in [
            ("Q", &operation.q, CurveV1::Pallas),
            ("A", &operation.a, CurveV1::Vesta),
            ("W", &operation.w, CurveV1::Pallas),
        ] {
            for index in indices {
                if let Some(previous) = members.insert(*index, (role, curve)) {
                    assert_eq!(previous, (role, curve), "private original role alias");
                }
            }
        }
    }
    assert!(!members.is_empty(), "private original coverage");
    let count = members.len();
    for (index, (role, curve)) in members {
        let original = inventory.member(index).expect("private role original");
        let bytes = read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
        let binding = DescriptorBinding::decode_v2(&bytes).unwrap();
        let d = binding.descriptor();
        assert_eq!(d.curve, curve);
        assert_eq!(d.transcript, TranscriptV2::KagemushaPoseidonRp57Base);
        assert_eq!(d.instance_mode, InstanceModeV1::Direct);
        assert_eq!(d.proof_suffix, ProofSuffixV1::FoldedGenerator);
        assert!(d.num_advice_columns > 0, "fresh first advice commitment");
        let key = read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1).unwrap();
        match curve {
            CurveV1::Pallas => {
                VerifyingKey::<Ep>::read(&key, &binding).unwrap();
            }
            CurveV1::Vesta => {
                VerifyingKey::<Eq>::read(&key, &binding).unwrap();
            }
        }
        let expected_bytes = key
            .len()
            .checked_add(108)
            .expect("compact private PK extent");
        let proving_key = read(source, original.proving_key, expected_bytes).unwrap();
        let rows = match curve {
            CurveV1::Pallas => {
                let rows = captured
                    .artifact_rows::<Fq>(&proving_key, &binding, &key)
                    .unwrap();
                check_boundary(d, &rows).unwrap();
                rows.len()
            }
            CurveV1::Vesta => {
                let rows = captured
                    .artifact_rows::<Fp>(&proving_key, &binding, &key)
                    .unwrap();
                check_boundary(d, &rows).unwrap();
                rows.len()
            }
        };
        assert_opening_mask(&binding, &format!("private.{role}.{index}"));
        eprintln!(
            "PRIVATE_MASK_BOUNDARY role={role} original={index} curve={curve:?} descriptor_sha256={} vk_sha256={} pk_sha256={} rows={rows} passed=true C12_closed=false",
            hex::encode(original.descriptor.sha256),
            hex::encode(original.verifying_key.sha256),
            hex::encode(original.proving_key.sha256),
        );
        // This original's owned bytes retire before the next member is read.
    }
    eprintln!("PRIVATE_MASK_COVERAGE originals={count} passed=true C12_closed=false");
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
        let rows = (0..8)
            .map(|row| {
                (
                    row,
                    Row {
                        fixed: vec![if row < 6 { Fq::ONE } else { Fq::ZERO }],
                        sigma: vec![
                            omega::<Fq>(3).pow_vartime([u64::try_from(row).unwrap()]),
                            Fq::DELTA * omega::<Fq>(3).pow_vartime([u64::try_from(row).unwrap()]),
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
    fn malformed_queries_and_expressions_refuse() {
        let (d, rows) = fixture();
        let mut changed = d.clone();
        changed.fixed_queries[0].column = 1;
        assert!(
            check_boundary(&changed, &rows)
                .unwrap_err()
                .contains("fixed query column")
        );
        for instance in [false, true] {
            let mut changed = d.clone();
            if instance {
                changed.instance_queries[0].column = 1;
            } else {
                changed.advice_queries[0].column = 1;
            }
            assert!(
                check_boundary(&changed, &rows)
                    .unwrap_err()
                    .contains("query column")
            );
        }
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
    fn arbitrary_rotations_close_previously_unchecked_boundary_rows() {
        for (rotation, row) in [(2, 4), (-2, 1), (6, 1)] {
            let (mut d, mut rows) = fixture();
            d.advice_queries[0].rotation = rotation;
            d.lookups.clear();
            // Isolate a nonzero selector at a row missed by the former
            // {0, usable-1, tail} scan. All tail fixed/copy checks still pass.
            for values in rows.values_mut() {
                values.fixed[0] = Fq::ZERO;
            }
            rows.get_mut(&row).unwrap().fixed[0] = Fq::ONE;
            assert!(![0, 5, 6, 7].contains(&row));
            assert!(boundary_rows(&d, 8, 6).unwrap().contains(&row));
            assert!(
                check_boundary(&d, &rows)
                    .unwrap_err()
                    .contains(&format!("gate tail dependence row={row}"))
            );
            rows.get_mut(&row).unwrap().fixed[0] = Fq::ZERO;
            check_boundary(&d, &rows).unwrap();
        }
        assert_eq!(rotated(0, i32::MIN, 8).unwrap(), 0);
        assert_eq!(rotated(1, i32::MAX, 8).unwrap(), 0);
    }

    #[test]
    fn rotated_fixed_lookup_selectors_use_the_actual_public_cell() {
        for input in [false, true] {
            let (mut d, mut rows) = fixture();
            d.advice_queries[0].rotation = 2;
            d.fixed_queries[0].rotation = -1;
            d.gates.clear();
            for values in rows.values_mut() {
                values.fixed[0] = Fq::ZERO;
            }
            // row4 reads advice6 (masked) and fixed3 (public, nonzero).
            // fixed4 is zero, so incorrectly ignoring the fixed rotation passes.
            rows.get_mut(&3).unwrap().fixed[0] = Fq::ONE;
            let expr = vec![
                ExprNodeV1::Fixed(0),
                ExprNodeV1::Advice(0),
                ExprNodeV1::Product,
            ];
            d.lookups[0].inputs = vec![vec![ExprNodeV1::Constant(Fq::ZERO.to_repr())]];
            d.lookups[0].tables = d.lookups[0].inputs.clone();
            if input {
                d.lookups[0].inputs[0] = expr;
            } else {
                d.lookups[0].tables[0] = expr;
            }
            assert!(!boundary_rows(&d, 8, 6).unwrap().contains(&3));
            assert!(public_table_rows(&d, 8, 6).unwrap().contains(&3));
            let error = check_boundary(&d, &rows).unwrap_err();
            assert!(error.contains("lookup tail dependence row=4"));
            assert!(error.contains(if input { "side=input" } else { "side=table" }));
            rows.get_mut(&3).unwrap().fixed[0] = Fq::ZERO;
            check_boundary(&d, &rows).unwrap();
            rows.remove(&3);
            assert!(
                check_boundary(&d, &rows)
                    .unwrap_err()
                    .contains("fixed row/column")
            );
        }
    }

    #[test]
    fn rotated_table_reader_keeps_closure_rows_and_refuses_missing_boundary() {
        let (mut d, mut rows) = fixture();
        d.advice_queries[0].rotation = 2;
        d.fixed_queries[0].rotation = -1;
        assert_eq!(
            boundary_rows(&d, 8, 6).unwrap(),
            BTreeSet::from([0, 4, 5, 6, 7])
        );
        assert_eq!(
            public_table_rows(&d, 8, 6).unwrap(),
            BTreeSet::from([0, 3, 4, 5, 6, 7])
        );
        for values in rows.values_mut() {
            values.fixed[0] = Fq::ZERO;
        }
        d.lookups.clear();
        check_boundary(&d, &rows).unwrap();
        rows.remove(&4);
        assert!(
            check_boundary(&d, &rows)
                .unwrap_err()
                .contains("missing boundary row")
        );
    }

    #[derive(Clone, Copy)]
    struct CompactSource {
        fixed: u64,
        copy: bool,
    }

    impl<F: iroha_pasta::PastaField> Circuit<F> for CompactSource {
        type Config = (
            iroha_plonk::cs::Column<iroha_plonk::cs::Advice>,
            iroha_plonk::cs::Column<iroha_plonk::cs::Advice>,
            iroha_plonk::cs::Column<iroha_plonk::cs::Fixed>,
            iroha_plonk::cs::Selector,
        );
        type FloorPlanner = iroha_plonk::frontend::SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(meta: &mut iroha_plonk::cs::ConstraintSystem<F>) -> Self::Config {
            use iroha_plonk::cs::Rotation;
            let a = meta.advice_column();
            let b = meta.advice_column();
            let fixed = meta.fixed_column();
            let selector = meta.selector();
            meta.enable_equality(a);
            meta.enable_equality(b);
            meta.create_gate("compact mask source", |cells| {
                vec![
                    cells.query_selector(selector)
                        * (cells.query_advice(a, Rotation(2))
                            * cells.query_fixed(fixed, Rotation(-1))
                            - cells.query_advice(b, Rotation::cur())),
                ]
            });
            (a, b, fixed, selector)
        }

        fn synthesize(
            &self,
            (a, b, fixed, selector): Self::Config,
            mut layouter: impl iroha_plonk::frontend::Layouter<F>,
        ) -> Result<(), iroha_plonk::frontend::Error> {
            use iroha_plonk::frontend::Value;
            layouter.assign_region(
                || "compact source",
                |mut region| {
                    let a = region.assign_advice(a, 0, Value::<F>::unknown())?.cell();
                    let b = region.assign_advice(b, 0, Value::<F>::unknown())?.cell();
                    region.assign_fixed(fixed, 0, F::from(self.fixed))?;
                    selector.enable(&mut region, 0)?;
                    if self.copy {
                        region.constrain_equal(a, b)?;
                    }
                    Ok(())
                },
            )
        }
    }

    fn compact_source_rows<C: PastaCurve>()
    where
        C::ScalarExt: MaskField,
    {
        use super::super::super::{OfflineCompilerV1, config};
        use super::super::{Originals, fixture_scope};
        use iroha_plonk::keys::CosetCachePolicy;
        let directory = tempfile::tempdir().unwrap();
        let mut originals = Originals {
            root: directory.path().to_owned(),
            bytes: 0,
            count: 0,
            new_write_remaining: 1 << 20,
        };
        let read_config = ReadConfig {
            maximum_bytes: 1 << 20,
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: iroha_pasta::msm::MemoryBudget::DEFAULT,
        };
        let params = PinnedParams::<C>::derive(6).unwrap();
        let circuit = CompactSource {
            fixed: 7,
            copy: true,
        };
        let mut compiler =
            OfflineCompilerV1::new(fixture_scope(), &mut originals, read_config, 1 << 20).unwrap();
        compiler.mask_rows = Some(ImportedRows::default());
        let key = compiler
            .key(&circuit, &params, &config(vec![], true, read_config))
            .unwrap();
        // Exercise fresh publication, indexed reuse, and final closure imports.
        let reused = compiler
            .key(&circuit, &params, &config(vec![], true, read_config))
            .unwrap();
        assert_eq!(key.original(), reused.original());
        assert_eq!(compiler.mask_rows.as_ref().unwrap().originals.len(), 1);
        assert_eq!(
            compiler.import(&key, &circuit, &params).unwrap().original(),
            key.original()
        );
        // Existing collected cells cannot bypass a changed exact native source.
        for changed in [
            CompactSource {
                fixed: 8,
                ..circuit
            },
            CompactSource {
                copy: false,
                ..circuit
            },
        ] {
            assert!(compiler.import(&key, &changed, &params).is_err());
        }
        let mut captured = compiler.mask_rows.take().unwrap();
        drop(compiler);
        let record = key.original();
        let descriptor = read(&mut originals, record.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
        let binding = DescriptorBinding::decode_v2(&descriptor).unwrap();
        let vk = read(
            &mut originals,
            record.verifying_key,
            VERIFYING_KEY_MAX_BYTES_V1,
        )
        .unwrap();
        let bytes = read(
            &mut originals,
            record.proving_key,
            read_config.maximum_bytes,
        )
        .unwrap();
        assert_eq!(&bytes[..8], b"PIPACPK1");
        assert_eq!(bytes.len(), 108 + vk.len());
        let typed =
            ProvingKey::from_artifact_v2(&bytes, &binding, &params, &circuit, read_config).unwrap();
        let rows = captured
            .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
            .unwrap();
        let (n, usable) = dimensions::<C::ScalarExt>(binding.descriptor()).unwrap();
        let closure = public_table_rows(binding.descriptor(), n, usable).unwrap();
        assert_eq!(rows.keys().copied().collect::<BTreeSet<_>>(), closure);
        assert!(!closure.is_subset(&boundary_rows(binding.descriptor(), n, usable).unwrap()));
        for (&row, values) in &rows {
            assert_eq!(
                values.fixed,
                typed
                    .fixed_values()
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                values.sigma,
                typed
                    .permutation_values()
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>()
            );
        }
        check_boundary(binding.descriptor(), &rows).unwrap();
        assert!(
            ImportedRows::default()
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
                .is_err()
        );
        let mut wrong = record;
        wrong.descriptor.sha256[0] ^= 1;
        assert!(!captured.contains(wrong));
        assert!(
            ImportedRows::default()
                .import(wrong, &bytes, &binding, &params, &circuit, read_config)
                .is_err()
        );
        wrong = record;
        wrong.verifying_key.sha256[0] ^= 1;
        assert!(!captured.contains(wrong));
        assert!(
            ImportedRows::default()
                .import(wrong, &bytes, &binding, &params, &circuit, read_config)
                .is_err()
        );
        let mut altered_vk = vk.clone();
        altered_vk[0] ^= 1;
        assert!(
            captured
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &altered_vk)
                .is_err()
        );
        for index in [0, 8, 40, 44, bytes.len() - 33, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            let changed_record = OriginalV1 {
                proving_key: BlobV1::of(&changed),
                ..record
            };
            assert!(
                ImportedRows::default()
                    .import(
                        changed_record,
                        &changed,
                        &binding,
                        &params,
                        &circuit,
                        read_config
                    )
                    .is_err()
            );
            assert!(
                captured
                    .artifact_rows::<C::ScalarExt>(&changed, &binding, &vk)
                    .is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut dense = bytes.clone();
        dense[..8].copy_from_slice(b"PIPAPK01");
        for changed in [bytes[..bytes.len() - 1].to_vec(), trailing, dense] {
            let changed_record = OriginalV1 {
                proving_key: BlobV1::of(&changed),
                ..record
            };
            assert!(
                ImportedRows::default()
                    .import(
                        changed_record,
                        &changed,
                        &binding,
                        &params,
                        &circuit,
                        read_config
                    )
                    .is_err()
            );
            assert!(
                captured
                    .artifact_rows::<C::ScalarExt>(&changed, &binding, &vk)
                    .is_err()
            );
        }
        let mut bounded = ImportedRows {
            bytes: MAX_CAPTURE_BYTES,
            ..ImportedRows::default()
        };
        assert!(
            bounded
                .import(record, &bytes, &binding, &params, &circuit, read_config)
                .unwrap_err()
                .contains("budget")
        );
        let entry = captured
            .originals
            .get_mut(&record.proving_key.sha256)
            .unwrap();
        let first = *entry.rows.keys().next().unwrap();
        let missing = entry.rows.remove(&first).unwrap();
        assert!(
            captured
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
                .unwrap_err()
                .contains("closure rows")
        );
        let entry = captured
            .originals
            .get_mut(&record.proving_key.sha256)
            .unwrap();
        entry.rows.insert(first, missing);
        entry.rows.get_mut(&first).unwrap().fixed[0] = [255; 32];
        assert!(
            captured
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
                .unwrap_err()
                .contains("noncanonical")
        );
        // Storage remains untrusted after collection: all final role assertions
        // use read() again, which refuses replacement and extent changes.
        let stored = directory
            .path()
            .join(hex::encode(record.proving_key.sha256));
        for changed in [
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), &[0]].concat(),
        ] {
            std::fs::write(&stored, changed).unwrap();
            assert!(
                read(
                    &mut originals,
                    record.proving_key,
                    read_config.maximum_bytes
                )
                .is_err()
            );
        }
    }

    #[test]
    fn compact_source_capture_preserves_exact_rows_and_refuses_substitution_on_both_curves() {
        compact_source_rows::<Ep>();
        compact_source_rows::<Eq>();
        let (d, _) = fixture();
        assert!(dimensions::<Fp>(&d).is_err());
    }

    #[test]
    fn fp_sigma_boundary_and_noncanonical_scalar_are_checked_in_fp() {
        let (mut d, _) = fixture();
        d.curve = CurveV1::Vesta;
        d.base_modulus = CurveV1::Vesta.base_modulus();
        d.scalar_modulus = CurveV1::Vesta.scalar_modulus();
        let mut rows: BTreeMap<usize, Row<Fp>> = (0..8)
            .map(|row| {
                let power = omega::<Fp>(3).pow_vartime([u64::try_from(row).unwrap()]);
                (
                    row,
                    Row {
                        fixed: vec![if row < 6 { Fp::ONE } else { Fp::ZERO }],
                        sigma: vec![power, Fp::DELTA * power],
                    },
                )
            })
            .collect();
        check_boundary(&d, &rows).unwrap();
        assert_eq!(canonical::<Fp>([255; 32]).unwrap_err(), "noncanonical Fp");
        rows.get_mut(&7).unwrap().sigma[0] += Fp::ONE;
        assert!(
            check_boundary(&d, &rows)
                .unwrap_err()
                .contains("tail copy not fixed")
        );
    }

    fn plan_queries() -> Vec<iroha_plonk::pcs::multiopen::OpeningQuery> {
        use iroha_plonk::pcs::multiopen::OpeningQuery;
        [
            (SlotKind::Advice, 0),
            (SlotKind::Advice, 1),
            (SlotKind::Advice, -1),
            (SlotKind::PermutationProduct, 0),
            (SlotKind::PermutationProduct, 1),
            (SlotKind::PermutationProduct, -6),
            (SlotKind::LookupPermutedInput, 0),
            (SlotKind::LookupPermutedInput, -1),
            // A synthetic public-only point set exercises the deterministic
            // branch; actual role profiles need not contain such a group.
            (SlotKind::Fixed, 2),
            (SlotKind::PermutationSigma, 2),
            (SlotKind::Vanishing, 0),
            (SlotKind::Random, 0),
        ]
        .into_iter()
        .map(|(kind, rotation)| OpeningQuery::new(Slot::new(kind, 0), rotation))
        .collect()
    }

    #[test]
    fn actual_plan_rank_keeps_public_only_groups_and_quotient_r_distinct() {
        let plan = OpeningPlan::new(&plan_queries()).unwrap();
        let report = opening_report(&plan, 64, 5).unwrap();
        assert!(
            report
                .iter()
                .any(|s| s.contains("fresh_rows=6 rank_with_x3=4 residual=2"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("fresh_rows=5 rank_with_x3=4 residual=1"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("exact_public_preprocessing"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("quotient_R_coefficient_one"))
        );
        assert!(
            report
                .iter()
                .any(|s| s.contains("residual_witness_pad_requires_nonzero_x1"))
        );
        // Query repetition does not create another evaluation constraint.
        let mut queries = plan_queries();
        queries.insert(1, queries[0]);
        let repeated = OpeningPlan::new(&queries).unwrap();
        assert_eq!(opening_report(&repeated, 64, 5).unwrap(), report);
    }

    #[test]
    fn quotient_mask_order_points_and_rotation_alias_mutations_refuse() {
        let queries = plan_queries();
        let mut missing = queries.clone();
        missing.pop();
        assert!(opening_report(&OpeningPlan::new(&missing).unwrap(), 64, 5).is_err());
        let mut reversed = queries.clone();
        let end = reversed.len();
        reversed.swap(end - 1, end - 2);
        assert!(
            opening_report(&OpeningPlan::new(&reversed).unwrap(), 64, 5)
                .unwrap_err()
                .contains("R not last")
        );
        let mut wrong_point = queries.clone();
        wrong_point.last_mut().unwrap().rotation = 1;
        assert!(
            opening_report(&OpeningPlan::new(&wrong_point).unwrap(), 64, 5)
                .unwrap_err()
                .contains("rotation zero")
        );
        let mut alias = queries;
        alias.insert(
            1,
            iroha_plonk::pcs::multiopen::OpeningQuery::new(Slot::new(SlotKind::Advice, 0), 64),
        );
        assert!(
            opening_report(&OpeningPlan::new(&alias).unwrap(), 64, 5)
                .unwrap_err()
                .contains("rotation alias")
        );
    }

    #[test]
    fn s7_and_direct_instance_profile_are_enforced_without_sampled_points() {
        use iroha_plonk::pcs::multiopen::OpeningQuery;
        let mut queries = plan_queries();
        queries.insert(1, OpeningQuery::new(Slot::new(SlotKind::Advice, 0), 3));
        assert!(
            opening_report(&OpeningPlan::new(&queries).unwrap(), 64, 5)
                .unwrap_err()
                .contains("S7")
        );
        let mut queries = plan_queries();
        queries.insert(0, OpeningQuery::new(Slot::new(SlotKind::Instance, 0), 0));
        assert!(
            opening_report(&OpeningPlan::new(&queries).unwrap(), 64, 5)
                .unwrap_err()
                .contains("Direct")
        );
        // Independent check through the production descriptor->Protocol path.
        let (mut d, _) = fixture();
        d.blinding_factors = 5;
        let protocol = Protocol::new(&d).unwrap();
        check_zero_knowledge_budget(&protocol).unwrap();
        opening_report(protocol.plan(), 8, 5).unwrap();
        d.blinding_factors = 4;
        assert!(check_zero_knowledge_budget(&Protocol::new(&d).unwrap()).is_err());
    }
}
